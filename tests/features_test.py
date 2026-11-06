#!/usr/bin/env python3
"""Tests for redundancy (mirror / erasure), index rebuild, readable buckets,
per-bucket key permissions, health/metrics, audit, replication and console
extras. Each test starts its own BoxSpace server(s).

    python3 tests/features_test.py [path/to/boxspace]
"""

import glob
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import time
import traceback
import zipfile

import requests
from boto3.s3.transfer import TransferConfig

sys.path.insert(0, os.path.dirname(__file__))
from compat_test import ROOT_PASS, ROOT_USER, Server, client, console_session, err_code  # noqa: E402

MP = TransferConfig(multipart_threshold=5 << 20, multipart_chunksize=5 << 20)


def objects_dir(disk, bucket):
    return os.path.join(disk, ".boxspace", "objects", bucket)


def data_files(disk, bucket, name):
    return glob.glob(os.path.join(objects_dir(disk, bucket), "*", "*", name))


def wait(cond, timeout=15, msg="condition"):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return
        time.sleep(0.2)
    raise AssertionError(f"timeout waiting for {msg}")


def heal_now(srv, deep=False):
    c = console_session(srv)
    before = c.get(f"{srv.curl}/api/system").json()["heal"].get("finished")
    assert c.post(f"{srv.curl}/api/system/heal", json={"deep": deep}).status_code == 200
    wait(lambda: (h := c.get(f"{srv.curl}/api/system").json()["heal"]).get("finished") not in (None, before) and not h["running"], msg="heal")
    return c.get(f"{srv.curl}/api/system").json()


def sample_objects(s3, bucket):
    """Put a mix of objects; returns {key: bytes}."""
    data = {
        "small.txt": b"hello mirror",
        "empty": b"",
        "mid.bin": os.urandom(3 * 1024 * 1024 + 17),
        "dir/sub/file.dat": os.urandom(100_000),
    }
    for k, v in data.items():
        s3.put_object(Bucket=bucket, Key=k, Body=v)
    big = os.urandom(11 * 1024 * 1024 + 5)
    s3.upload_fileobj(io.BytesIO(big), bucket, "multi.bin", Config=MP)
    data["multi.bin"] = big
    s3.put_object(Bucket=bucket, Key="secret.bin", Body=b"S" * 200_000, ServerSideEncryption="AES256")
    data["secret.bin"] = b"S" * 200_000
    return data


def check_all(s3, bucket, data):
    for k, v in data.items():
        got = s3.get_object(Bucket=bucket, Key=k)["Body"].read()
        assert got == v, f"{k}: {len(got)} != {len(v)}"
    k = "mid.bin"
    assert s3.get_object(Bucket=bucket, Key=k, Range="bytes=1048570-2097160")["Body"].read() == data[k][1048570:2097161]


# ------------------------------------------------------------------ tests ----

def t_mirror(binary):
    srv = Server(binary, disks=2)
    try:
        s3 = client(srv)
        s3.create_bucket(Bucket="mir")
        data = sample_objects(s3, "mir")
        assert len(data_files(srv.disks[0], "mir", "data")) == len(data_files(srv.disks[1], "mir", "data")) > 0
        # Lose disk 0's copies: reads fall back to disk 1.
        shutil.rmtree(objects_dir(srv.disks[0], "mir"))
        check_all(s3, "mir", data)
        st = heal_now(srv)
        assert st["heal"]["healed"] >= len(data) - 1, st["heal"]
        assert len(data_files(srv.disks[0], "mir", "data")) == len(data_files(srv.disks[1], "mir", "data"))
        # Replace disk 1 entirely while stopped.
        srv.proc.terminate()
        srv.proc.wait(10)
        shutil.rmtree(srv.disks[1])
        srv.start()
        wait(lambda: len(data_files(srv.disks[1], "mir", "data")) == len(data_files(srv.disks[0], "mir", "data")), msg="disk 1 rebuilt")
        shutil.rmtree(objects_dir(srv.disks[0], "mir"))
        check_all(s3, "mir", data)  # served entirely from the rebuilt disk
    finally:
        srv.stop()


def t_erasure(binary):
    srv = Server(binary, disks=4, args=["--redundancy", "erasure", "--parity", "2"])
    try:
        s3 = client(srv)
        s3.create_bucket(Bucket="ecb")
        data = sample_objects(s3, "ecb")
        for d in srv.disks:
            assert data_files(d, "ecb", "shard"), "every disk holds shards"
            assert not data_files(d, "ecb", "data"), "no full copies in erasure mode"
        # Lose two whole disks' shards: still readable.
        for d in srv.disks[:2]:
            for f in data_files(d, "ecb", "shard"):
                os.chmod(f, 0o644)
                os.remove(f)
        check_all(s3, "ecb", data)
        st = heal_now(srv)
        assert not st["heal"]["lost"] and st["heal"]["healed"] >= len(data) - 1, st["heal"]
        counts = [len(data_files(d, "ecb", "shard")) for d in srv.disks]
        assert len(set(counts)) == 1, counts
        # Bitrot: flip a byte in one shard. Reads detect the CRC mismatch and
        # use parity; a deep check rewrites the shard.
        mid = s3.head_object(Bucket="ecb", Key="mid.bin")
        victim = max(data_files(srv.disks[2], "ecb", "shard"), key=os.path.getsize)
        os.chmod(victim, 0o644)
        with open(victim, "r+b") as fh:
            fh.seek(10)
            b = fh.read(1)
            fh.seek(10)
            fh.write(bytes([b[0] ^ 0xFF]))
        check_all(s3, "ecb", data)
        before = open(victim, "rb").read()
        st = heal_now(srv, deep=True)
        assert not st["heal"]["lost"] and st["heal"]["healed"] >= 1, st["heal"]
        assert open(victim, "rb").read() != before, "corrupt shard rewritten"
        assert mid["ContentLength"] == len(data["mid.bin"])
        # After healing, any two disks are enough again.
        for d in srv.disks[2:]:
            for f in data_files(d, "ecb", "shard"):
                os.chmod(f, 0o644)
                os.remove(f)
        check_all(s3, "ecb", data)
        # Three disks gone (more than the parity): the object is unavailable.
        for f in data_files(srv.disks[0], "ecb", "shard"):
            os.chmod(f, 0o644)
            os.remove(f)
        assert err_code(s3.get_object, Bucket="ecb", Key="mid.bin") == "SlowDown"
        assert err_code(s3.get_object, Bucket="ecb", Key="multi.bin") == "SlowDown"
        h = requests.get(f"{srv.url}/_boxspace/health").json()
        assert h["mode"] == "erasure" and h["disks"] == 4
    finally:
        srv.stop()


def t_rebuild(binary):
    srv = Server(binary, disks=2)
    try:
        s3 = client(srv)
        s3.create_bucket(Bucket="rbk")
        s3.put_bucket_versioning(Bucket="rbk", VersioningConfiguration={"Status": "Enabled"})
        v1 = s3.put_object(Bucket="rbk", Key="doc", Body=b"one")["VersionId"]
        s3.put_object(Bucket="rbk", Key="doc", Body=b"two", Tagging="a=b")
        s3.upload_fileobj(io.BytesIO(b"x" * (6 << 20)), "rbk", "big", Config=MP)
        s3.delete_object(Bucket="rbk", Key="gone-later")
        c = console_session(srv)
        key = c.post(f"{srv.curl}/api/keys", json={"description": "app"}).json()
        time.sleep(0.5)  # let config files reach the disks
        srv.proc.terminate()
        srv.proc.wait(10)
        os.remove(os.path.join(srv.disks[0], ".boxspace", "meta.redb"))
        srv.start()
        assert s3.get_object(Bucket="rbk", Key="doc")["Body"].read() == b"two"
        assert s3.get_object(Bucket="rbk", Key="doc", VersionId=v1)["Body"].read() == b"one"
        assert s3.get_object_tagging(Bucket="rbk", Key="doc")["TagSet"] == [{"Key": "a", "Value": "b"}]
        assert s3.get_object(Bucket="rbk", Key="big")["Body"].read() == b"x" * (6 << 20)
        assert s3.get_bucket_versioning(Bucket="rbk")["Status"] == "Enabled"
        k = client(srv, ak=key["accessKey"], sk=key["secretKey"])
        assert k.get_object(Bucket="rbk", Key="doc")["Body"].read() == b"two"
        listed = [o["Key"] for o in s3.list_objects_v2(Bucket="rbk")["Contents"]]
        assert listed == ["big", "doc"], listed
        assert c.get(f"{srv.curl}/api/buckets/rbk").status_code in (200, 401)
        c = console_session(srv)
        assert c.get(f"{srv.curl}/api/buckets/rbk").json()["objects"] == 2
    finally:
        srv.stop()


def t_readable(binary):
    srv = Server(binary, disks=2)
    try:
        s3 = client(srv)
        c = console_session(srv)
        assert c.post(f"{srv.curl}/api/buckets", json={"name": "fotos", "readable": True}).status_code == 200
        root = os.path.join(srv.disks[0], "fotos")
        s3.put_object(Bucket="fotos", Key="2026/praia.jpg", Body=b"JPEGDATA")
        p = os.path.join(root, "2026", "praia.jpg")
        assert open(p, "rb").read() == b"JPEGDATA"
        assert os.stat(p).st_nlink == 1, "independent of the stored data"
        # Editing the readable file (root ignores 0444) must not change the object.
        os.chmod(p, 0o644)
        with open(p, "r+b") as fh:
            fh.write(b"XXXX")
        assert s3.get_object(Bucket="fotos", Key="2026/praia.jpg")["Body"].read() == b"JPEGDATA"
        s3.put_object(Bucket="fotos", Key="2026/praia.jpg", Body=b"NEWDATA")
        assert open(p, "rb").read() == b"NEWDATA"
        s3.put_object(Bucket="fotos", Key="pasta-vazia/", Body=b"")
        assert os.path.isdir(os.path.join(root, "pasta-vazia"))
        big = os.urandom(7 << 20)
        s3.upload_fileobj(io.BytesIO(big), "fotos", "videos/clip.mp4", Config=MP)
        assert open(os.path.join(root, "videos", "clip.mp4"), "rb").read() == big
        s3.delete_object(Bucket="fotos", Key="2026/praia.jpg")
        assert not os.path.exists(p) and not os.path.exists(os.path.join(root, "2026")), "file removed, empty folder pruned"
        # Unsafe names are stored but not exposed.
        s3.put_object(Bucket="fotos", Key="a/../../escape", Body=b"x")
        assert not os.path.exists(os.path.join(srv.disks[0], "escape"))
        info = c.get(f"{srv.curl}/api/buckets/fotos/object", params={"key": "videos/clip.mp4"}).json()
        assert info["diskPath"].endswith("fotos/videos/clip.mp4"), info
        # Encryption and readable files exclude each other.
        assert c.put(f"{srv.curl}/api/buckets/fotos/encryption", json={"enabled": True}).status_code == 400
        # Enabling on an existing bucket backfills; disabling removes the folder.
        s3.create_bucket(Bucket="docs")
        s3.put_object(Bucket="docs", Key="a/b.txt", Body=b"b")
        s3.put_object(Bucket="docs", Key="c.txt", Body=b"c")
        assert c.put(f"{srv.curl}/api/buckets/docs/readable", json={"enabled": True}).status_code == 200
        wait(lambda: os.path.exists(os.path.join(srv.disks[0], "docs", "a", "b.txt")), msg="backfill")
        assert open(os.path.join(srv.disks[0], "docs", "c.txt")).read() == "c"
        assert c.put(f"{srv.curl}/api/buckets/docs/readable", json={"enabled": False}).status_code == 200
        assert not os.path.exists(os.path.join(srv.disks[0], "docs"))
        # Versioned bucket: delete marker hides the file, removing it restores it.
        s3.put_bucket_versioning(Bucket="fotos", VersioningConfiguration={"Status": "Enabled"})
        s3.put_object(Bucket="fotos", Key="v.txt", Body=b"v1")
        m = s3.delete_object(Bucket="fotos", Key="v.txt")["VersionId"]
        assert not os.path.exists(os.path.join(root, "v.txt"))
        s3.delete_object(Bucket="fotos", Key="v.txt", VersionId=m)
        assert open(os.path.join(root, "v.txt")).read() == "v1"
    finally:
        srv.stop()


def t_grants(binary):
    srv = Server(binary)
    try:
        s3 = client(srv)
        for b in ["alpha", "wr-one", "secret"]:
            s3.create_bucket(Bucket=b)
            s3.put_object(Bucket=b, Key="f", Body=b)
        c = console_session(srv)
        k = c.post(f"{srv.curl}/api/keys", json={"grants": [{"bucket": "alpha", "write": False}, {"bucket": "wr-*", "write": True}]}).json()
        kc = client(srv, ak=k["accessKey"], sk=k["secretKey"])
        assert sorted(b["Name"] for b in kc.list_buckets()["Buckets"]) == ["alpha", "wr-one"]
        assert kc.get_object(Bucket="alpha", Key="f")["Body"].read() == b"alpha"
        assert err_code(kc.put_object, Bucket="alpha", Key="x", Body=b"x") == "AccessDenied"
        kc.put_object(Bucket="wr-one", Key="x", Body=b"x")
        assert err_code(kc.get_object, Bucket="secret", Key="f") == "AccessDenied"
        assert err_code(kc.create_bucket, Bucket="wr-new") == "AccessDenied"
        assert err_code(kc.put_bucket_versioning, Bucket="wr-one", VersioningConfiguration={"Status": "Enabled"}) == "AccessDenied"
        # Copy from a readable bucket into a writable one is allowed.
        kc.copy_object(Bucket="wr-one", Key="copied", CopySource="alpha/f")
        # Console respects the same grants.
        kcs = console_session(srv, k["accessKey"], k["secretKey"])
        assert sorted(b["name"] for b in kcs.get(f"{srv.curl}/api/buckets").json()) == ["alpha", "wr-one"]
        assert kcs.get(f"{srv.curl}/api/buckets/secret/objects").status_code == 403
        assert kcs.put(f"{srv.curl}/api/buckets/alpha/object", params={"key": "n"}, data=b"n").status_code == 403
        # Updating grants applies immediately.
        r = c.put(f"{srv.curl}/api/keys/{k['accessKey']}", json={"grants": [{"bucket": "*", "write": True}]})
        assert r.status_code == 200, r.text
        kc.put_object(Bucket="alpha", Key="now-ok", Body=b"x")
    finally:
        srv.stop()


def t_health_metrics_audit(binary):
    srv = Server(binary)
    try:
        s3 = client(srv)
        assert requests.get(f"{srv.url}/_boxspace/health/live").text.strip() == "ok"
        h = requests.get(f"{srv.url}/_boxspace/health")
        assert h.status_code == 200 and h.json()["status"] == "ok", h.text
        assert requests.get(f"{srv.url}/_boxspace/metrics").status_code == 403
        s3.create_bucket(Bucket="obs")
        s3.put_object(Bucket="obs", Key="a", Body=b"12345")
        err_code(s3.get_object, Bucket="obs", Key="missing")
        m = requests.get(f"{srv.url}/_boxspace/metrics", headers={"Authorization": "Bearer metrics-token"})
        assert m.status_code == 200, m.text
        assert 'boxspace_requests_total{op="PutObject",status="200"} 1' in m.text, m.text[:2000]
        assert 'boxspace_requests_total{op="GetObject",status="404"} 1' in m.text
        assert 'boxspace_bucket_objects{bucket="obs"} 1' in m.text
        assert 'boxspace_bucket_bytes{bucket="obs"} 5' in m.text
        assert "boxspace_disk_online" in m.text
        r = subprocess.run([srv.binary, "healthcheck", f"{srv.url}/_boxspace/health"])
        assert r.returncode == 0
        r = subprocess.run([srv.binary, "healthcheck", "http://127.0.0.1:1/_boxspace/health"])
        assert r.returncode == 1
        # Audit
        c = console_session(srv)
        c.post(f"{srv.curl}/api/buckets", json={"name": "from-console"})
        time.sleep(0.3)
        files = glob.glob(os.path.join(srv.disks[0], ".boxspace", "audit", "audit-*.jsonl"))
        assert files
        lines = [json.loads(line) for f in files for line in open(f)]
        put = [e for e in lines if e["op"] == "PutObject"]
        assert put and put[0]["accessKey"] == ROOT_USER and put[0]["bucket"] == "obs" and put[0]["bytesIn"] == 5, put
        assert any(e["source"] == "console" and "/api/buckets" in e["op"] for e in lines)
        res = c.get(f"{srv.curl}/api/audit", params={"errors": "1"}).json()
        assert res["enabled"] and all(e["status"] >= 400 for e in res["entries"]) and res["entries"]
        res = c.get(f"{srv.curl}/api/audit", params={"op": "putobject"}).json()
        assert [e["op"] for e in res["entries"]] == ["PutObject"]
    finally:
        srv.stop()


def t_replication(binary):
    src = Server(binary)
    dst = Server(binary)
    try:
        s3 = client(src)
        d3 = client(dst)
        s3.create_bucket(Bucket="origem")
        d3.create_bucket(Bucket="destino")
        s3.put_object(Bucket="origem", Key="antes.txt", Body=b"existed before")
        c = console_session(src)
        target = {"endpoint": dst.url, "bucket": "destino", "region": "us-east-1", "accessKey": ROOT_USER,
                  "secretKey": ROOT_PASS, "prefix": "", "replicateDeletes": True, "enabled": True}
        assert c.post(f"{src.curl}/api/buckets/origem/replication/test", json=target).json()["ok"]
        bad = dict(target, secretKey="wrong-secret")
        assert not c.post(f"{src.curl}/api/buckets/origem/replication/test", json=bad).json()["ok"]
        r = c.put(f"{src.curl}/api/buckets/origem/replication", json={"targets": [target]})
        assert r.status_code == 200 and r.json()["queued"] == 1, r.text
        s3.put_object(Bucket="origem", Key="novo.txt", Body=b"new", Metadata={"m": "1"}, ContentType="text/plain", Tagging="t=1")
        big = os.urandom(70 * 1024 * 1024)
        s3.upload_fileobj(io.BytesIO(big), "origem", "grande.bin", Config=TransferConfig(multipart_threshold=16 << 20, multipart_chunksize=16 << 20))

        def present(k):
            try:
                d3.head_object(Bucket="destino", Key=k)
                return True
            except Exception:
                return False
        wait(lambda: present("antes.txt") and present("novo.txt") and present("grande.bin"), timeout=60, msg="replication")
        o = d3.get_object(Bucket="destino", Key="novo.txt")
        assert o["Body"].read() == b"new" and o["Metadata"] == {"m": "1"} and o["ContentType"] == "text/plain"
        assert d3.get_object_tagging(Bucket="destino", Key="novo.txt")["TagSet"] == [{"Key": "t", "Value": "1"}]
        assert hashlib.md5(d3.get_object(Bucket="destino", Key="grande.bin")["Body"].read()).digest() == hashlib.md5(big).digest()
        s3.delete_object(Bucket="origem", Key="novo.txt")
        wait(lambda: not present("novo.txt"), timeout=30, msg="delete replicated")
        # Writes made by replication are not replicated back (no loops).
        d3.create_bucket(Bucket="volta")
        dc = console_session(dst)
        back = dict(target, endpoint=src.url, bucket="origem")
        assert dc.put(f"{dst.curl}/api/buckets/destino/replication", json={"targets": [back]}).status_code == 200
        s3.put_object(Bucket="origem", Key="loop.txt", Body=b"loop")
        wait(lambda: present("loop.txt"), timeout=30, msg="replicated")
        time.sleep(2)
        st = c.get(f"{src.curl}/api/buckets/origem").json()["replicationStats"]
        assert st["pending"] == 0 and st["failed"] == 0, st
        listed = c.get(f"{src.curl}/api/buckets/origem").json()["replication"][0]
        assert "secretKey" not in listed and "secretEnc" not in listed
    finally:
        src.stop()
        dst.stop()


def t_console_extras(binary):
    srv = Server(binary)
    try:
        s3 = client(srv)
        s3.create_bucket(Bucket="extras")
        for k in ["relatorios/2026/Janeiro.pdf", "relatorios/2026/fevereiro.pdf", "fotos/janela.png", "outros/x.txt"]:
            s3.put_object(Bucket="extras", Key=k, Body=k.encode(), ContentType="application/pdf" if k.endswith("pdf") else "image/png" if k.endswith("png") else "text/plain")
        c = console_session(srv)
        r = c.get(f"{srv.curl}/api/buckets/extras/search", params={"q": "jan"}).json()
        assert sorted(o["key"] for o in r["objects"]) == ["fotos/janela.png", "relatorios/2026/Janeiro.pdf"], r
        # ZIP of a folder plus a file.
        tok = c.post(f"{srv.curl}/api/buckets/extras/zip", json={"keys": ["outros/x.txt"], "prefixes": ["relatorios/"]}).json()["token"]
        z = c.get(f"{srv.curl}/api/zip/{tok}")
        assert z.status_code == 200 and z.headers["content-type"] == "application/zip"
        zf = zipfile.ZipFile(io.BytesIO(z.content))
        assert zf.testzip() is None
        names = sorted(zf.namelist())
        assert names == ["outros/x.txt", "relatorios/2026/Janeiro.pdf", "relatorios/2026/fevereiro.pdf"], names
        assert zf.read("outros/x.txt") == b"outros/x.txt"
        assert c.get(f"{srv.curl}/api/zip/{tok}").status_code == 400, "tokens are single use"
        # Previews are sandboxed.
        p = c.get(f"{srv.curl}/api/buckets/extras/download", params={"key": "fotos/janela.png", "inline": "1"})
        assert p.status_code == 200 and p.headers["content-type"] == "image/png"
        assert p.headers["content-security-policy"].startswith("sandbox")
        assert p.headers["content-disposition"].startswith("inline")
        s3.put_object(Bucket="extras", Key="page.html", Body=b"<script>alert(1)</script>", ContentType="text/html")
        p = c.get(f"{srv.curl}/api/buckets/extras/download", params={"key": "page.html", "inline": "1"})
        assert p.headers["content-type"].startswith("text/plain"), "HTML is never rendered"
        # Bulk delete, counters follow.
        r = c.post(f"{srv.curl}/api/buckets/extras/bulk-delete", json={"keys": ["outros/x.txt"], "prefixes": ["relatorios/"]}).json()
        assert r["deleted"] == 3
        b = c.get(f"{srv.curl}/api/buckets/extras").json()
        assert b["objects"] == 2 and b["bytes"] == len(b"fotos/janela.png") + len(b"<script>alert(1)</script>"), b
    finally:
        srv.stop()


def t_listing_scale(binary):
    srv = Server(binary)
    try:
        s3 = client(srv)
        s3.create_bucket(Bucket="many")
        from concurrent.futures import ThreadPoolExecutor
        keys = [f"logs/{i:05d}" for i in range(3000)] + ["readme"] + [f"z/{i}" for i in range(50)]
        with ThreadPoolExecutor(16) as ex:
            list(ex.map(lambda k: s3.put_object(Bucket="many", Key=k, Body=b"x"), keys))
        t = time.time()
        for _ in range(20):
            r = s3.list_objects_v2(Bucket="many", Delimiter="/")
        per = (time.time() - t) / 20
        assert [p["Prefix"] for p in r["CommonPrefixes"]] == ["logs/", "z/"] and [o["Key"] for o in r["Contents"]] == ["readme"]
        assert per < 0.05, f"delimiter listing took {per:.3f}s (should skip subfolders)"
    finally:
        srv.stop()


def t_heal_gc(binary):
    """Cleanup never removes referenced data, even when it is old."""
    srv = Server(binary, disks=2)
    try:
        s3 = client(srv)
        s3.create_bucket(Bucket="gcb")
        s3.put_object(Bucket="gcb", Key="kept", Body=b"kept")
        u = s3.create_multipart_upload(Bucket="gcb", Key="slow")["UploadId"]
        p1 = s3.upload_part(Bucket="gcb", Key="slow", UploadId=u, PartNumber=1, Body=b"a" * (5 << 20))
        p2 = s3.upload_part(Bucket="gcb", Key="slow", UploadId=u, PartNumber=2, Body=b"tail")
        # A true orphan (e.g. an interrupted write) in both disks.
        orphans = []
        for d in srv.disks:
            o = os.path.join(objects_dir(d, "gcb"), "ff", "ff00orphan")
            os.makedirs(o)
            open(os.path.join(o, "data"), "wb").write(b"junk")
            orphans.append(o)
        # Make everything look two hours old.
        old = time.time() - 7200
        for d in srv.disks:
            for root, dirs, files in os.walk(objects_dir(d, "gcb")):
                for n in dirs + files:
                    os.utime(os.path.join(root, n), (old, old))
        st = heal_now(srv)
        assert st["heal"]["orphans"] == 2, st["heal"]
        assert not any(os.path.exists(o) for o in orphans)
        s3.complete_multipart_upload(Bucket="gcb", Key="slow", UploadId=u, MultipartUpload={"Parts": [
            {"PartNumber": 1, "ETag": p1["ETag"]}, {"PartNumber": 2, "ETag": p2["ETag"]}]})
        assert s3.get_object(Bucket="gcb", Key="slow")["Body"].read() == b"a" * (5 << 20) + b"tail"
        assert s3.get_object(Bucket="gcb", Key="kept")["Body"].read() == b"kept"
        # A failed completion leaves the upload usable.
        u2 = s3.create_multipart_upload(Bucket="gcb", Key="retry")["UploadId"]
        q = s3.upload_part(Bucket="gcb", Key="retry", UploadId=u2, PartNumber=1, Body=b"z")
        assert err_code(s3.complete_multipart_upload, Bucket="gcb", Key="retry", UploadId=u2,
                        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": '"bad"'}]}) == "InvalidPart"
        s3.complete_multipart_upload(Bucket="gcb", Key="retry", UploadId=u2, MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": q["ETag"]}]})
        assert s3.get_object(Bucket="gcb", Key="retry")["Body"].read() == b"z"
        # Deleting and recreating a bucket starts empty and stays usable.
        s3.delete_object(Bucket="gcb", Key="kept")
        s3.delete_object(Bucket="gcb", Key="slow")
        s3.delete_object(Bucket="gcb", Key="retry")
        s3.delete_bucket(Bucket="gcb")
        s3.create_bucket(Bucket="gcb")
        s3.put_object(Bucket="gcb", Key="new", Body=b"new")
        assert s3.get_object(Bucket="gcb", Key="new")["Body"].read() == b"new"
    finally:
        srv.stop()


def t_ipfilter(binary):
    srv = Server(binary, env={"BOXSPACE_TRUST_PROXY": "1"})
    try:
        def s3_from(ip, sk=ROOT_PASS):
            c = client(srv, sk=sk)
            c.meta.events.register("before-sign.s3", lambda request, **kw: request.headers.__setitem__("X-Forwarded-For", ip))
            return c

        def health(ip):
            return requests.get(f"{srv.url}/_boxspace/health", headers={"X-Forwarded-For": ip}).status_code

        admin_ip = "198.51.100.10"
        c = console_session(srv)
        c.headers["X-Forwarded-For"] = admin_ip
        s3_from(admin_ip).create_bucket(Bucket="ipt")
        cfg = c.get(f"{srv.curl}/api/ipfilter").json()
        assert cfg["yourIp"] == admin_ip and cfg["config"]["mode"] == "blocklist", cfg
        conf = cfg["config"]

        # Manual block of a range, API only.
        conf["rules"] = [{"cidr": "203.0.113.0/24", "action": "block", "scope": "api", "note": "teste"}]
        assert c.put(f"{srv.curl}/api/ipfilter", json=conf).status_code == 200
        assert err_code(s3_from("203.0.113.5").list_buckets) == "AccessDenied"
        assert health("203.0.113.200") == 403
        assert health("203.0.114.1") == 200
        r = requests.get(f"{srv.curl}/", headers={"X-Forwarded-For": "203.0.113.5"})
        assert r.status_code == 200, "scope=api leaves the console open"
        assert s3_from("192.0.2.1").list_buckets()["Buckets"]
        assert requests.get(f"{srv.url}/_boxspace/health").status_code == 200, "loopback is never blocked"

        # Expired rules are ignored; invalid ranges are rejected.
        conf["rules"].append({"cidr": "192.0.2.0/24", "action": "block", "scope": "all", "expires": "2020-01-01T00:00:00Z"})
        assert c.put(f"{srv.curl}/api/ipfilter", json=conf).status_code == 200
        assert health("192.0.2.9") == 200
        bad = dict(conf, rules=[{"cidr": "10.0.0.0/40", "action": "block", "scope": "all"}])
        assert c.put(f"{srv.curl}/api/ipfilter", json=bad).status_code == 400

        # Lockout protection: cannot block your own console access.
        selfblock = dict(conf, rules=[{"cidr": "198.51.100.0/24", "action": "block", "scope": "all"}])
        r = c.put(f"{srv.curl}/api/ipfilter", json=selfblock)
        assert r.status_code == 400 and admin_ip in r.json()["error"], r.text
        allowlist = dict(conf, mode="allowlist", rules=[])
        assert c.put(f"{srv.curl}/api/ipfilter", json=allowlist).status_code == 400
        allowlist["rules"] = [{"cidr": "198.51.100.0/24", "action": "allow", "scope": "all"}, {"cidr": "2001:db8::/32", "action": "allow", "scope": "api"}]
        assert c.put(f"{srv.curl}/api/ipfilter", json=allowlist).status_code == 200
        assert health("192.0.2.1") == 403
        assert health("198.51.100.77") == 200
        assert health("2001:db8::5") == 200
        assert requests.get(f"{srv.curl}/", headers={"X-Forwarded-For": "2001:db8::5"}).status_code == 403, "IPv6 allow was API only"

        # Automatic ban after repeated failures (S3 and console logins).
        conf = dict(mode="blocklist", rules=[], auto={"enabled": True, "maxFailures": 3, "windowSecs": 60, "banSecs": 600})
        assert c.put(f"{srv.curl}/api/ipfilter", json=conf).status_code == 200
        attacker = "192.0.2.66"
        for _ in range(3):
            assert err_code(s3_from(attacker, sk="wrong-secret").list_buckets) == "SignatureDoesNotMatch"
        assert err_code(s3_from(attacker).list_buckets) == "AccessDenied", "banned even with the right key"
        guesser = "192.0.2.77"
        for _ in range(3):
            requests.post(f"{srv.curl}/api/login", json={"accessKey": ROOT_USER, "secretKey": "nope"}, headers={"X-Forwarded-For": guesser})
        r = requests.post(f"{srv.curl}/api/login", json={"accessKey": ROOT_USER, "secretKey": ROOT_PASS}, headers={"X-Forwarded-For": guesser})
        assert r.status_code == 403, r.status_code
        bans = {b["ip"] for b in c.get(f"{srv.curl}/api/ipfilter").json()["bans"]}
        assert bans == {attacker, guesser}, bans
        assert c.delete(f"{srv.curl}/api/ipfilter/bans/{attacker}").json()["ok"]
        assert s3_from(attacker).list_buckets()["Buckets"]
        # Allow rules exempt an address from automatic bans.
        conf["rules"] = [{"cidr": "192.0.2.88", "action": "allow", "scope": "all"}]
        assert c.put(f"{srv.curl}/api/ipfilter", json=conf).status_code == 200
        for _ in range(5):
            err_code(s3_from("192.0.2.88", sk="wrong").list_buckets)
        assert s3_from("192.0.2.88").list_buckets()["Buckets"]

        # Audit, metrics, persistence.
        time.sleep(0.3)
        lines = [json.loads(line) for f in glob.glob(os.path.join(srv.disks[0], ".boxspace", "audit", "*.jsonl")) for line in open(f)]
        assert any(e["op"] == "IpBanned" and e["remote"] == attacker for e in lines)
        assert any(e["op"] == "IpBlocked" for e in lines)
        m = requests.get(f"{srv.url}/_boxspace/metrics", headers={"Authorization": "Bearer metrics-token"}).text
        assert "boxspace_ip_blocked_total" in m and "boxspace_ip_bans_total 2" in m, m[-800:]

        # Anonymous scanners: many refused requests without credentials ban the address,
        # while presigned-looking requests (with credentials) are not counted.
        conf["auto"]["maxDenied"] = 5
        assert c.put(f"{srv.curl}/api/ipfilter", json=conf).status_code == 200
        assert c.get(f"{srv.curl}/api/ipfilter").json()["config"]["auto"]["maxDenied"] == 5
        scanner = "192.0.2.99"
        for path in ["/.env", "/.git/config", "/core/", "/api/", "/backup.zip"]:
            r = requests.get(f"{srv.url}{path}", headers={"X-Forwarded-For": scanner})
            assert r.status_code == 403, (path, r.status_code)
        assert health(scanner) == 403, "scanner banned"
        bans = {b["ip"]: b for b in c.get(f"{srv.curl}/api/ipfilter").json()["bans"]}
        assert bans[scanner]["reason"] == "denied", bans
        expired = "192.0.2.98"
        for _ in range(8):
            requests.get(f"{srv.url}/core/x?X-Amz-Credential=a&X-Amz-Signature=b", headers={"X-Forwarded-For": expired})
        assert health(expired) == 200, "requests with credentials are not counted as anonymous"
        assert c.delete(f"{srv.curl}/api/ipfilter/bans/{scanner}").json()["ok"]
        conf["rules"].append({"cidr": "203.0.113.0/24", "action": "block", "scope": "all"})
        assert c.put(f"{srv.curl}/api/ipfilter", json=conf).status_code == 200
        srv.restart()
        assert health("203.0.113.1") == 403, "rules survive a restart"
        assert health(guesser) == 200, "automatic bans end on restart"
    finally:
        srv.stop()


TESTS = [t_mirror, t_heal_gc, t_ipfilter, t_erasure, t_rebuild, t_readable, t_grants, t_health_metrics_audit, t_replication, t_console_extras, t_listing_scale]


def main():
    binary = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "target", "debug", "boxspace"))
    only = sys.argv[2:] if len(sys.argv) > 2 else None
    failed = 0
    run = [t for t in TESTS if not only or t.__name__ in only]
    for t in run:
        start = time.time()
        try:
            t(binary)
            print(f"  ok    {t.__name__} ({time.time() - start:.1f}s)")
        except Exception:
            failed += 1
            print(f"  FAIL  {t.__name__}")
            traceback.print_exc()
    print(f"\n{len(run) - failed}/{len(run)} testes de recursos passaram")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""End-to-end S3 compatibility tests for BoxSpace using boto3.

Starts a BoxSpace server on random ports with a temporary data directory,
runs the tests and reports results.

    python3 tests/compat_test.py [path/to/boxspace]
"""

import base64
import datetime
import hashlib
import hmac
import http.server
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import zlib

import boto3
import requests
from botocore.config import Config
from botocore.exceptions import ClientError

ROOT_USER = "testadmin"
ROOT_PASS = "testsecret123"
REGION = "us-east-1"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Server:
    def __init__(self, binary):
        self.dir = tempfile.mkdtemp(prefix="boxspace-test-")
        self.port = free_port()
        self.cport = free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.curl = f"http://127.0.0.1:{self.cport}"
        env = dict(os.environ)
        env.update(
            BOXSPACE_ROOT_USER=ROOT_USER,
            BOXSPACE_ROOT_PASSWORD=ROOT_PASS,
            BOXSPACE_SERVER_URL=self.url,
            BOXSPACE_LIFECYCLE_INTERVAL="1",
            BOXSPACE_LIFECYCLE_DAY_SECONDS="2",
            RUST_LOG="warn",
        )
        self.log = open(os.path.join(self.dir, "server.log"), "w")
        self.proc = subprocess.Popen(
            [binary, "server", "--address", f"127.0.0.1:{self.port}", "--console-address", f"127.0.0.1:{self.cport}", os.path.join(self.dir, "data")],
            env=env, stdout=self.log, stderr=subprocess.STDOUT,
        )
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.port), 0.2).close()
                socket.create_connection(("127.0.0.1", self.cport), 0.2).close()
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("server did not start")

    def stop(self):
        self.proc.terminate()
        self.proc.wait(10)
        self.log.close()


def client(server, ak=ROOT_USER, sk=ROOT_PASS, **cfg):
    return boto3.client(
        "s3", endpoint_url=server.url, aws_access_key_id=ak, aws_secret_access_key=sk, region_name=REGION,
        config=Config(s3={"addressing_style": "path"}, signature_version="s3v4", retries={"max_attempts": 1}, **cfg),
    )


def err_code(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except ClientError as e:
        return e.response["Error"]["Code"]
    return None


def console_session(server, ak=ROOT_USER, sk=ROOT_PASS):
    s = requests.Session()
    s.headers["x-boxspace-csrf"] = "1"
    r = s.post(f"{server.curl}/api/login", json={"accessKey": ak, "secretKey": sk})
    assert r.status_code == 200, r.text
    return s


# ---------------------------------------------------------------- tests ----

def t_buckets(srv, s3):
    assert s3.list_buckets()["Buckets"] == []
    s3.create_bucket(Bucket="alpha")
    s3.create_bucket(Bucket="beta")
    names = [b["Name"] for b in s3.list_buckets()["Buckets"]]
    assert names == ["alpha", "beta"], names
    s3.head_bucket(Bucket="alpha")
    assert err_code(s3.head_bucket, Bucket="missing") in ("404", "NoSuchBucket")
    assert err_code(s3.create_bucket, Bucket="alpha") == "BucketAlreadyOwnedByYou"
    assert err_code(s3.create_bucket, Bucket="Bad_Name") == "InvalidBucketName"
    assert s3.get_bucket_location(Bucket="alpha")["LocationConstraint"] in (None, "")
    s3.delete_bucket(Bucket="beta")
    assert [b["Name"] for b in s3.list_buckets()["Buckets"]] == ["alpha"]


def t_objects(srv, s3):
    data = b"hello boxspace\n" * 1000
    r = s3.put_object(Bucket="alpha", Key="docs/hello.txt", Body=data, ContentType="text/plain",
                      Metadata={"author": "diogenes", "acentos": "sim"}, CacheControl="max-age=60")
    assert r["ETag"] == '"%s"' % hashlib.md5(data).hexdigest()
    g = s3.get_object(Bucket="alpha", Key="docs/hello.txt")
    assert g["Body"].read() == data
    assert g["ContentType"] == "text/plain"
    assert g["Metadata"] == {"author": "diogenes", "acentos": "sim"}, g["Metadata"]
    assert g["CacheControl"] == "max-age=60"
    h = s3.head_object(Bucket="alpha", Key="docs/hello.txt")
    assert h["ContentLength"] == len(data), h["ContentLength"]
    # Ranges
    assert s3.get_object(Bucket="alpha", Key="docs/hello.txt", Range="bytes=6-13")["Body"].read() == b"boxspace"
    assert s3.get_object(Bucket="alpha", Key="docs/hello.txt", Range="bytes=-6")["Body"].read() == data[-6:]
    assert err_code(s3.get_object, Bucket="alpha", Key="docs/hello.txt", Range="bytes=999999-") == "InvalidRange"
    # Conditionals
    assert err_code(s3.get_object, Bucket="alpha", Key="docs/hello.txt", IfNoneMatch=r["ETag"]) == "304"
    assert err_code(s3.get_object, Bucket="alpha", Key="docs/hello.txt", IfMatch='"abc"') == "PreconditionFailed"
    assert err_code(s3.put_object, Bucket="alpha", Key="docs/hello.txt", Body=b"x", IfNoneMatch="*") == "PreconditionFailed"
    # Empty object
    s3.put_object(Bucket="alpha", Key="empty", Body=b"")
    assert s3.get_object(Bucket="alpha", Key="empty")["Body"].read() == b""
    assert err_code(s3.get_object, Bucket="alpha", Key="nope") == "NoSuchKey"
    assert err_code(s3.get_object, Bucket="nobucket", Key="nope") == "NoSuchBucket"
    # Bad Content-MD5
    assert err_code(s3.put_object, Bucket="alpha", Key="bad", Body=b"abc",
                    ContentMD5=base64.b64encode(hashlib.md5(b"xyz").digest()).decode()) == "BadDigest"
    s3.delete_object(Bucket="alpha", Key="empty")
    assert err_code(s3.head_object, Bucket="alpha", Key="empty") == "404"


def t_special_keys(srv, s3):
    keys = ["com espaço.txt", "ação/ünïcødé ✓.txt", "a+b=c&d.txt", "pct%20lit.txt", "q?x#y.txt", "dir//double/slash", "~tilde", "日本語/ファイル"]
    for k in keys:
        s3.put_object(Bucket="alpha", Key=k, Body=k.encode())
        assert s3.get_object(Bucket="alpha", Key=k)["Body"].read() == k.encode(), k
    listed = [o["Key"] for o in s3.list_objects_v2(Bucket="alpha")["Contents"]]
    for k in keys:
        assert k in listed, (k, listed)
    listed_v1 = [o["Key"] for o in s3.list_objects(Bucket="alpha")["Contents"]]
    assert set(keys) <= set(listed_v1)
    s3.delete_objects(Bucket="alpha", Delete={"Objects": [{"Key": k} for k in keys]})
    listed = [o["Key"] for o in s3.list_objects_v2(Bucket="alpha").get("Contents", [])]
    assert not (set(keys) & set(listed)), listed


def t_listing(srv, s3):
    s3.create_bucket(Bucket="lst")
    keys = [f"logs/2026/{i:02d}.log" for i in range(25)] + ["logs/readme", "photos/a.jpg", "photos/b/c.jpg", "top.txt"]
    for k in keys:
        s3.put_object(Bucket="lst", Key=k, Body=b"x")
    got = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket="lst", PaginationConfig={"PageSize": 7}):
        got += [o["Key"] for o in page.get("Contents", [])]
    assert got == sorted(keys), got
    got = []
    for page in s3.get_paginator("list_objects").paginate(Bucket="lst", PaginationConfig={"PageSize": 4}):
        got += [o["Key"] for o in page.get("Contents", [])]
    assert got == sorted(keys)
    r = s3.list_objects_v2(Bucket="lst", Delimiter="/")
    assert [p["Prefix"] for p in r["CommonPrefixes"]] == ["logs/", "photos/"]
    assert [o["Key"] for o in r["Contents"]] == ["top.txt"]
    r = s3.list_objects_v2(Bucket="lst", Prefix="photos/", Delimiter="/")
    assert [o["Key"] for o in r["Contents"]] == ["photos/a.jpg"]
    assert [p["Prefix"] for p in r["CommonPrefixes"]] == ["photos/b/"]
    # Pagination with delimiter and common prefixes
    items = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket="lst", Delimiter="/", Prefix="logs/", PaginationConfig={"PageSize": 1}):
        items += [o["Key"] for o in page.get("Contents", [])] + [p["Prefix"] for p in page.get("CommonPrefixes", [])]
    assert items == ["logs/2026/", "logs/readme"], items
    r = s3.list_objects_v2(Bucket="lst", StartAfter="logs/2026/23.log", MaxKeys=2)
    assert [o["Key"] for o in r["Contents"]] == ["logs/2026/24.log", "logs/readme"]
    assert r["KeyCount"] == 2 and r["IsTruncated"]


def t_copy(srv, s3):
    s3.put_object(Bucket="alpha", Key="src.txt", Body=b"copy me", ContentType="text/plain", Metadata={"k": "v"})
    r = s3.copy_object(Bucket="alpha", Key="dst.txt", CopySource={"Bucket": "alpha", "Key": "src.txt"})
    assert r["CopyObjectResult"]["ETag"] == '"%s"' % hashlib.md5(b"copy me").hexdigest()
    g = s3.get_object(Bucket="alpha", Key="dst.txt")
    assert g["Body"].read() == b"copy me" and g["Metadata"] == {"k": "v"} and g["ContentType"] == "text/plain"
    s3.copy_object(Bucket="alpha", Key="dst2.txt", CopySource="alpha/src.txt", MetadataDirective="REPLACE",
                   Metadata={"new": "1"}, ContentType="application/x-test")
    h = s3.head_object(Bucket="alpha", Key="dst2.txt")
    assert h["Metadata"] == {"new": "1"} and h["ContentType"] == "application/x-test"
    assert err_code(s3.copy_object, Bucket="alpha", Key="src.txt", CopySource="alpha/src.txt") == "InvalidRequest"
    s3.copy_object(Bucket="alpha", Key="src.txt", CopySource="alpha/src.txt", MetadataDirective="REPLACE", Metadata={"x": "y"})
    assert err_code(s3.copy_object, Bucket="alpha", Key="x", CopySource="alpha/missing") == "NoSuchKey"
    assert err_code(s3.copy_object, Bucket="alpha", Key="x", CopySource="alpha/src.txt", CopySourceIfMatch='"nope"') == "PreconditionFailed"


def t_multipart(srv, s3):
    from boto3.s3.transfer import TransferConfig
    data = os.urandom(23 * 1024 * 1024 + 123)
    cfg = TransferConfig(multipart_threshold=5 * 1024 * 1024, multipart_chunksize=5 * 1024 * 1024, max_concurrency=4)
    s3.upload_fileobj(io.BytesIO(data), "alpha", "big/file.bin", Config=cfg)
    h = s3.head_object(Bucket="alpha", Key="big/file.bin")
    assert h["ContentLength"] == len(data)
    assert h["ETag"].strip('"').endswith("-5"), h["ETag"]
    out = io.BytesIO()
    s3.download_fileobj("alpha", "big/file.bin", out, Config=cfg)
    assert out.getvalue() == data
    assert s3.get_object(Bucket="alpha", Key="big/file.bin", Range="bytes=10485750-10485770")["Body"].read() == data[10485750:10485771]
    # Manual API: list parts, abort, list uploads, too-small parts.
    u = s3.create_multipart_upload(Bucket="alpha", Key="mp/manual", ContentType="text/csv", Metadata={"m": "1"})
    uid = u["UploadId"]
    p1 = s3.upload_part(Bucket="alpha", Key="mp/manual", UploadId=uid, PartNumber=1, Body=b"a" * (5 * 1024 * 1024))
    p2 = s3.upload_part(Bucket="alpha", Key="mp/manual", UploadId=uid, PartNumber=2, Body=b"tail")
    parts = s3.list_parts(Bucket="alpha", Key="mp/manual", UploadId=uid)["Parts"]
    assert [p["PartNumber"] for p in parts] == [1, 2] and parts[1]["Size"] == 4
    ups = s3.list_multipart_uploads(Bucket="alpha")["Uploads"]
    assert uid in [x["UploadId"] for x in ups]
    assert err_code(s3.complete_multipart_upload, Bucket="alpha", Key="mp/manual", UploadId=uid,
                    MultipartUpload={"Parts": [{"PartNumber": 2, "ETag": p2["ETag"]}, {"PartNumber": 1, "ETag": p1["ETag"]}]}) == "InvalidPartOrder"
    assert err_code(s3.complete_multipart_upload, Bucket="alpha", Key="mp/manual", UploadId=uid,
                    MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": '"deadbeef"'}]}) == "InvalidPart"
    s3.complete_multipart_upload(Bucket="alpha", Key="mp/manual", UploadId=uid,
                                 MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": p1["ETag"]}, {"PartNumber": 2, "ETag": p2["ETag"]}]})
    g = s3.get_object(Bucket="alpha", Key="mp/manual")
    assert g["ContentType"] == "text/csv" and g["Metadata"] == {"m": "1"}
    assert g["Body"].read() == b"a" * (5 * 1024 * 1024) + b"tail"
    assert err_code(s3.list_parts, Bucket="alpha", Key="mp/manual", UploadId=uid) == "NoSuchUpload"
    # Too small
    u = s3.create_multipart_upload(Bucket="alpha", Key="mp/small")
    a = s3.upload_part(Bucket="alpha", Key="mp/small", UploadId=u["UploadId"], PartNumber=1, Body=b"tiny")
    b = s3.upload_part(Bucket="alpha", Key="mp/small", UploadId=u["UploadId"], PartNumber=2, Body=b"tiny")
    assert err_code(s3.complete_multipart_upload, Bucket="alpha", Key="mp/small", UploadId=u["UploadId"],
                    MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": a["ETag"]}, {"PartNumber": 2, "ETag": b["ETag"]}]}) == "EntityTooSmall"
    s3.abort_multipart_upload(Bucket="alpha", Key="mp/small", UploadId=u["UploadId"])
    assert err_code(s3.list_parts, Bucket="alpha", Key="mp/small", UploadId=u["UploadId"]) == "NoSuchUpload"
    # Upload part copy
    u = s3.create_multipart_upload(Bucket="alpha", Key="mp/copied")
    c1 = s3.upload_part_copy(Bucket="alpha", Key="mp/copied", UploadId=u["UploadId"], PartNumber=1,
                             CopySource="alpha/big/file.bin", CopySourceRange="bytes=0-5242879")
    c2 = s3.upload_part_copy(Bucket="alpha", Key="mp/copied", UploadId=u["UploadId"], PartNumber=2,
                             CopySource="alpha/big/file.bin", CopySourceRange="bytes=5242880-5242889")
    s3.complete_multipart_upload(Bucket="alpha", Key="mp/copied", UploadId=u["UploadId"],
                                 MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": c1["CopyPartResult"]["ETag"]},
                                                            {"PartNumber": 2, "ETag": c2["CopyPartResult"]["ETag"]}]})
    assert s3.get_object(Bucket="alpha", Key="mp/copied")["Body"].read() == data[:5242890]


def t_presigned(srv, s3):
    s3.put_object(Bucket="alpha", Key="share/me.txt", Body=b"shared content")
    url = s3.generate_presigned_url("get_object", Params={"Bucket": "alpha", "Key": "share/me.txt"}, ExpiresIn=60)
    r = requests.get(url)
    assert r.status_code == 200 and r.content == b"shared content", (r.status_code, r.text)
    # Tampered signature
    assert requests.get(url[:-4] + "0000").status_code == 403
    # Presigned PUT
    put_url = s3.generate_presigned_url("put_object", Params={"Bucket": "alpha", "Key": "share/uploaded.txt"}, ExpiresIn=60)
    r = requests.put(put_url, data=b"via presigned put")
    assert r.status_code == 200, r.text
    assert s3.get_object(Bucket="alpha", Key="share/uploaded.txt")["Body"].read() == b"via presigned put"
    # Expired
    url = s3.generate_presigned_url("get_object", Params={"Bucket": "alpha", "Key": "share/me.txt"}, ExpiresIn=1)
    time.sleep(2.1)
    r = requests.get(url)
    assert r.status_code == 403 and b"expired" in r.content, r.text
    # Anonymous access without a policy
    assert requests.get(f"{srv.url}/alpha/share/me.txt").status_code == 403


def t_versioning(srv, s3):
    s3.create_bucket(Bucket="ver")
    assert "Status" not in s3.get_bucket_versioning(Bucket="ver")
    s3.put_object(Bucket="ver", Key="f", Body=b"before")  # null version
    s3.put_bucket_versioning(Bucket="ver", VersioningConfiguration={"Status": "Enabled"})
    assert s3.get_bucket_versioning(Bucket="ver")["Status"] == "Enabled"
    v1 = s3.put_object(Bucket="ver", Key="f", Body=b"one")["VersionId"]
    v2 = s3.put_object(Bucket="ver", Key="f", Body=b"two")["VersionId"]
    assert v1 != v2
    assert s3.get_object(Bucket="ver", Key="f")["Body"].read() == b"two"
    assert s3.get_object(Bucket="ver", Key="f", VersionId=v1)["Body"].read() == b"one"
    assert s3.get_object(Bucket="ver", Key="f", VersionId="null")["Body"].read() == b"before"
    vs = s3.list_object_versions(Bucket="ver")
    assert [v["VersionId"] for v in vs["Versions"]] == [v2, v1, "null"]
    assert [v["IsLatest"] for v in vs["Versions"]] == [True, False, False]
    d = s3.delete_object(Bucket="ver", Key="f")
    assert d["DeleteMarker"] is True
    marker = d["VersionId"]
    assert err_code(s3.get_object, Bucket="ver", Key="f") == "NoSuchKey"
    assert "Contents" not in s3.list_objects_v2(Bucket="ver")
    vs = s3.list_object_versions(Bucket="ver")
    assert vs["DeleteMarkers"][0]["VersionId"] == marker and vs["DeleteMarkers"][0]["IsLatest"]
    assert err_code(s3.get_object, Bucket="ver", Key="f", VersionId=marker) == "MethodNotAllowed"
    # Removing the marker restores the object
    s3.delete_object(Bucket="ver", Key="f", VersionId=marker)
    assert s3.get_object(Bucket="ver", Key="f")["Body"].read() == b"two"
    # Permanently delete a version
    s3.delete_object(Bucket="ver", Key="f", VersionId=v2)
    assert s3.get_object(Bucket="ver", Key="f")["Body"].read() == b"one"
    # Version listing pagination
    for i in range(5):
        s3.put_object(Bucket="ver", Key="g", Body=str(i).encode())
    seen = []
    for page in s3.get_paginator("list_object_versions").paginate(Bucket="ver", PaginationConfig={"PageSize": 2}):
        seen += [(v["Key"], v["VersionId"]) for v in page.get("Versions", [])]
    assert len(seen) == 7 and len(set(seen)) == 7, seen
    # Suspend: new writes go to the "null" version
    s3.put_bucket_versioning(Bucket="ver", VersioningConfiguration={"Status": "Suspended"})
    r = s3.put_object(Bucket="ver", Key="g", Body=b"null-a")
    s3.put_object(Bucket="ver", Key="g", Body=b"null-b")
    nulls = [v for v in s3.list_object_versions(Bucket="ver", Prefix="g")["Versions"] if v["VersionId"] == "null"]
    assert len(nulls) == 1
    assert err_code(s3.delete_bucket, Bucket="ver") == "BucketNotEmpty"


def t_tagging(srv, s3):
    s3.put_object(Bucket="alpha", Key="tagged", Body=b"x", Tagging="env=prod&team=core")
    t = s3.get_object_tagging(Bucket="alpha", Key="tagged")["TagSet"]
    assert sorted((x["Key"], x["Value"]) for x in t) == [("env", "prod"), ("team", "core")]
    assert s3.head_object(Bucket="alpha", Key="tagged")["ResponseMetadata"]["HTTPHeaders"]["x-amz-tagging-count"] == "2"
    s3.put_object_tagging(Bucket="alpha", Key="tagged", Tagging={"TagSet": [{"Key": "a", "Value": "b c"}]})
    assert s3.get_object_tagging(Bucket="alpha", Key="tagged")["TagSet"] == [{"Key": "a", "Value": "b c"}]
    s3.delete_object_tagging(Bucket="alpha", Key="tagged")
    assert s3.get_object_tagging(Bucket="alpha", Key="tagged")["TagSet"] == []
    assert err_code(s3.get_bucket_tagging, Bucket="alpha") == "NoSuchTagSet"
    s3.put_bucket_tagging(Bucket="alpha", Tagging={"TagSet": [{"Key": "owner", "Value": "me"}]})
    assert s3.get_bucket_tagging(Bucket="alpha")["TagSet"] == [{"Key": "owner", "Value": "me"}]
    s3.delete_bucket_tagging(Bucket="alpha")
    assert err_code(s3.get_bucket_tagging, Bucket="alpha") == "NoSuchTagSet"
    too_many = {"TagSet": [{"Key": f"k{i}", "Value": "v"} for i in range(11)]}
    assert err_code(s3.put_object_tagging, Bucket="alpha", Key="tagged", Tagging=too_many) == "InvalidTag"


def t_policy(srv, s3):
    s3.create_bucket(Bucket="pub")
    s3.put_object(Bucket="pub", Key="img/logo.png", Body=b"PNG")
    assert requests.get(f"{srv.url}/pub/img/logo.png").status_code == 403
    assert err_code(s3.get_bucket_policy, Bucket="pub") == "NoSuchBucketPolicy"
    pol = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::pub/*"]},
        {"Effect": "Allow", "Principal": {"AWS": ["*"]}, "Action": ["s3:ListBucket"], "Resource": ["arn:aws:s3:::pub"]},
        {"Effect": "Deny", "Principal": "*", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::pub/private/*"]}]}
    s3.put_bucket_policy(Bucket="pub", Policy=json.dumps(pol))
    assert json.loads(s3.get_bucket_policy(Bucket="pub")["Policy"]) == pol
    r = requests.get(f"{srv.url}/pub/img/logo.png")
    assert r.status_code == 200 and r.content == b"PNG"
    r = requests.get(f"{srv.url}/pub?list-type=2")
    assert r.status_code == 200 and b"img/logo.png" in r.content
    s3.put_object(Bucket="pub", Key="private/x", Body=b"secret")
    assert requests.get(f"{srv.url}/pub/private/x").status_code == 403
    assert requests.put(f"{srv.url}/pub/hack.txt", data=b"x").status_code == 403
    assert requests.delete(f"{srv.url}/pub/img/logo.png").status_code == 403
    bad = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::other/*"}]}
    assert err_code(s3.put_bucket_policy, Bucket="pub", Policy=json.dumps(bad)) == "MalformedPolicy"
    s3.delete_bucket_policy(Bucket="pub")
    assert requests.get(f"{srv.url}/pub/img/logo.png").status_code == 403


def t_cors(srv, s3):
    s3.put_bucket_cors(Bucket="alpha", CORSConfiguration={"CORSRules": [
        {"AllowedOrigins": ["https://app.example.com"], "AllowedMethods": ["GET", "PUT"], "AllowedHeaders": ["*"],
         "ExposeHeaders": ["ETag"], "MaxAgeSeconds": 600}]})
    rules = s3.get_bucket_cors(Bucket="alpha")["CORSRules"]
    assert rules[0]["AllowedOrigins"] == ["https://app.example.com"] and rules[0]["MaxAgeSeconds"] == 600
    r = requests.options(f"{srv.url}/alpha/docs/hello.txt", headers={
        "Origin": "https://app.example.com", "Access-Control-Request-Method": "PUT", "Access-Control-Request-Headers": "content-type"})
    assert r.status_code == 200, r.text
    assert r.headers["Access-Control-Allow-Origin"] == "https://app.example.com"
    assert r.headers["Access-Control-Max-Age"] == "600"
    r = requests.options(f"{srv.url}/alpha/x", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert r.status_code == 403
    url = s3.generate_presigned_url("get_object", Params={"Bucket": "alpha", "Key": "docs/hello.txt"})
    r = requests.get(url, headers={"Origin": "https://app.example.com"})
    assert r.headers.get("Access-Control-Allow-Origin") == "https://app.example.com"
    assert r.headers.get("Access-Control-Expose-Headers") == "ETag"
    s3.delete_bucket_cors(Bucket="alpha")
    assert err_code(s3.get_bucket_cors, Bucket="alpha") == "NoSuchCORSConfiguration"


def t_encryption(srv, s3):
    s3.create_bucket(Bucket="enc")
    assert err_code(s3.get_bucket_encryption, Bucket="enc") == "ServerSideEncryptionConfigurationNotFoundError"
    s3.put_bucket_encryption(Bucket="enc", ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
    rule = s3.get_bucket_encryption(Bucket="enc")["ServerSideEncryptionConfiguration"]["Rules"][0]
    assert rule["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] == "AES256"
    marker = b"PLAINTEXT-MARKER-0123456789"
    data = (marker + os.urandom(100)) * 3000  # ~380 KB, several 64 KiB chunks
    r = s3.put_object(Bucket="enc", Key="secret.bin", Body=data)
    assert r["ServerSideEncryption"] == "AES256"
    assert s3.get_object(Bucket="enc", Key="secret.bin")["Body"].read() == data
    for a, b in [(0, 0), (65530, 65545), (131071, 131072), (len(data) - 10, len(data) - 1), (100, 300000)]:
        got = s3.get_object(Bucket="enc", Key="secret.bin", Range=f"bytes={a}-{b}")["Body"].read()
        assert got == data[a:b + 1], (a, b)
    assert s3.head_object(Bucket="enc", Key="secret.bin")["ServerSideEncryption"] == "AES256"
    # Data on disk must not contain the plaintext.
    blobs = os.path.join(srv.dir, "data", ".boxspace", "blobs", "enc")
    found = False
    for root, _, files in os.walk(blobs):
        for f in files:
            with open(os.path.join(root, f), "rb") as fh:
                content = fh.read()
            assert marker not in content, "plaintext found on disk"
            found = True
    assert found
    # Per-object SSE on an unencrypted bucket, multipart + copy into encrypted bucket.
    r = s3.put_object(Bucket="alpha", Key="sse-one", Body=b"x" * 10, ServerSideEncryption="AES256")
    assert r["ServerSideEncryption"] == "AES256"
    s3.copy_object(Bucket="enc", Key="copied", CopySource="alpha/docs/hello.txt")
    assert s3.head_object(Bucket="enc", Key="copied")["ServerSideEncryption"] == "AES256"
    from boto3.s3.transfer import TransferConfig
    big = os.urandom(11 * 1024 * 1024)
    s3.upload_fileobj(io.BytesIO(big), "enc", "big", Config=TransferConfig(multipart_threshold=5 << 20, multipart_chunksize=5 << 20))
    assert s3.get_object(Bucket="enc", Key="big")["Body"].read() == big
    assert err_code(s3.put_object, Bucket="enc", Key="kms", Body=b"x", ServerSideEncryption="aws:kms") == "NotImplemented"
    s3.put_object(Bucket="enc", Key="empty", Body=b"")
    assert s3.get_object(Bucket="enc", Key="empty")["Body"].read() == b""


def t_lifecycle(srv, s3):
    s3.create_bucket(Bucket="life")
    s3.put_bucket_lifecycle_configuration(Bucket="life", LifecycleConfiguration={"Rules": [
        {"ID": "tmp", "Filter": {"Prefix": "tmp/"}, "Status": "Enabled", "Expiration": {"Days": 1},
         "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1}}]})
    rules = s3.get_bucket_lifecycle_configuration(Bucket="life")["Rules"]
    assert rules[0]["ID"] == "tmp" and rules[0]["Expiration"]["Days"] == 1
    s3.put_object(Bucket="life", Key="tmp/a", Body=b"a")
    s3.put_object(Bucket="life", Key="keep/b", Body=b"b")
    s3.create_multipart_upload(Bucket="life", Key="tmp/upload")
    # "1 day" = 2 seconds in the test server; the job runs every second.
    deadline = time.time() + 10
    while time.time() < deadline:
        keys = [o["Key"] for o in s3.list_objects_v2(Bucket="life").get("Contents", [])]
        if keys == ["keep/b"] and not s3.list_multipart_uploads(Bucket="life").get("Uploads"):
            break
        time.sleep(0.5)
    assert keys == ["keep/b"], keys
    assert not s3.list_multipart_uploads(Bucket="life").get("Uploads")
    s3.delete_bucket_lifecycle(Bucket="life")
    assert err_code(s3.get_bucket_lifecycle_configuration, Bucket="life") == "NoSuchLifecycleConfiguration"


def t_auth(srv, s3):
    bad = client(srv, sk="wrong-secret")
    assert err_code(bad.list_buckets) == "SignatureDoesNotMatch"
    unknown = client(srv, ak="NOPE", sk="x")
    assert err_code(unknown.list_buckets) == "InvalidAccessKeyId"
    assert requests.get(srv.url + "/").status_code == 403
    r = requests.get(srv.url + "/alpha", headers={"Authorization": "AWS abc:def"})
    assert r.status_code == 501


def sigv4_streaming_put(srv, bucket, key, data, chunk=65536, unsigned_trailer=False):
    """Hand-rolled aws-chunked upload (what mc / Java SDK send over HTTP)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = amz_date[:8]
    scope = f"{date}/{REGION}/s3/aws4_request"
    host = f"127.0.0.1:{srv.port}"
    path = f"/{bucket}/{key}"

    def h(k, m):
        return hmac.new(k, m.encode() if isinstance(m, str) else m, hashlib.sha256).digest()
    skey = h(h(h(h(("AWS4" + ROOT_PASS).encode(), date), REGION), "s3"), "aws4_request")
    mode = "STREAMING-UNSIGNED-PAYLOAD-TRAILER" if unsigned_trailer else "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
    headers = {"host": host, "x-amz-content-sha256": mode, "x-amz-date": amz_date,
               "x-amz-decoded-content-length": str(len(data)), "content-encoding": "aws-chunked"}
    if unsigned_trailer:
        headers["x-amz-trailer"] = "x-amz-checksum-crc32"
    signed = ";".join(sorted(headers))
    canonical = "\n".join(["PUT", path, "", "".join(f"{k}:{headers[k]}\n" for k in sorted(headers)), signed, mode])
    sts = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    seed = hmac.new(skey, sts.encode(), hashlib.sha256).hexdigest()
    body = b""
    prev = seed
    pieces = [data[i:i + chunk] for i in range(0, len(data), chunk)] + [b""]
    for p in pieces:
        if unsigned_trailer:
            body += f"{len(p):x}\r\n".encode() + (p + b"\r\n" if p else b"")
        else:
            csts = "\n".join(["AWS4-HMAC-SHA256-PAYLOAD", amz_date, scope, prev, hashlib.sha256(b"").hexdigest(), hashlib.sha256(p).hexdigest()])
            sig = hmac.new(skey, csts.encode(), hashlib.sha256).hexdigest()
            body += f"{len(p):x};chunk-signature={sig}\r\n".encode() + p + b"\r\n"
            prev = sig
    if unsigned_trailer:
        crc = base64.b64encode(zlib.crc32(data).to_bytes(4, "big")).decode()
        body += f"x-amz-checksum-crc32:{crc}\r\n\r\n".encode()
    headers["authorization"] = f"AWS4-HMAC-SHA256 Credential={ROOT_USER}/{scope}, SignedHeaders={signed}, Signature={seed}"
    return requests.put(f"{srv.url}{path}", data=body, headers=headers)


def t_streaming(srv, s3):
    data = os.urandom(300_000)
    r = sigv4_streaming_put(srv, "alpha", "stream/signed.bin", data)
    assert r.status_code == 200, r.text
    assert s3.get_object(Bucket="alpha", Key="stream/signed.bin")["Body"].read() == data
    r = sigv4_streaming_put(srv, "alpha", "stream/trailer.bin", data, unsigned_trailer=True)
    assert r.status_code == 200, r.text
    assert s3.get_object(Bucket="alpha", Key="stream/trailer.bin")["Body"].read() == data
    # A chunk whose bytes were altered in transit must be rejected.
    orig = requests.put

    def tamper(url, data=None, headers=None):
        flipped = data[:500] + bytes([data[500] ^ 1]) + data[501:]  # inside the first chunk's payload
        return orig(url, data=flipped, headers=headers)

    requests.put = tamper
    try:
        r = sigv4_streaming_put(srv, "alpha", "stream/tampered.bin", data)
    finally:
        requests.put = orig
    assert r.status_code == 403, (r.status_code, r.text)
    assert err_code(s3.head_object, Bucket="alpha", Key="stream/tampered.bin") == "404"
    # Default boto3 behaviour (checksums when supported) also works.
    s3c = client(srv, request_checksum_calculation="when_supported")
    s3c.put_object(Bucket="alpha", Key="stream/boto-default", Body=io.BytesIO(data))
    assert s3c.get_object(Bucket="alpha", Key="stream/boto-default")["Body"].read() == data


def t_console(srv, s3):
    r = requests.post(f"{srv.curl}/api/login", json={"accessKey": ROOT_USER, "secretKey": "bad"})
    assert r.status_code == 401
    assert requests.get(f"{srv.curl}/api/buckets").status_code == 401
    c = console_session(srv)
    page = c.get(f"{srv.curl}/")
    assert page.status_code == 200 and "BoxSpace" in page.text
    assert page.headers["X-Frame-Options"] == "DENY"
    info = c.get(f"{srv.curl}/api/info").json()
    assert info["buckets"] >= 1, info
    # CSRF header is required for writes
    raw = requests.Session()
    raw.cookies = c.cookies
    assert raw.post(f"{srv.curl}/api/buckets", json={"name": "csrf-test"}).status_code == 403
    assert c.post(f"{srv.curl}/api/buckets", json={"name": "console-bkt"}).status_code == 200
    assert c.post(f"{srv.curl}/api/buckets", json={"name": "Bad Name"}).status_code == 400
    r = c.put(f"{srv.curl}/api/buckets/console-bkt/object", params={"key": "pasta/arquivo ç.txt"}, data=b"conteudo", headers={"content-type": "text/plain"})
    assert r.status_code == 200, r.text
    assert s3.get_object(Bucket="console-bkt", Key="pasta/arquivo ç.txt")["Body"].read() == b"conteudo"
    lst = c.get(f"{srv.curl}/api/buckets/console-bkt/objects").json()
    assert lst["prefixes"] == ["pasta/"], lst
    lst = c.get(f"{srv.curl}/api/buckets/console-bkt/objects", params={"prefix": "pasta/"}).json()
    assert lst["objects"][0]["key"] == "pasta/arquivo ç.txt"
    d = c.get(f"{srv.curl}/api/buckets/console-bkt/download", params={"key": "pasta/arquivo ç.txt"})
    assert d.content == b"conteudo" and "attachment" in d.headers["content-disposition"]
    share = c.post(f"{srv.curl}/api/buckets/console-bkt/share", json={"key": "pasta/arquivo ç.txt", "expires": 300}).json()
    assert requests.get(share["url"]).content == b"conteudo", share
    # Settings
    assert c.put(f"{srv.curl}/api/buckets/console-bkt/versioning", json={"enabled": True}).status_code == 200
    assert s3.get_bucket_versioning(Bucket="console-bkt")["Status"] == "Enabled"
    assert c.put(f"{srv.curl}/api/buckets/console-bkt/policy", json={"mode": "public-read"}).status_code == 200
    assert requests.get(f"{srv.url}/console-bkt/pasta/arquivo%20%C3%A7.txt").content == b"conteudo"
    assert c.put(f"{srv.curl}/api/buckets/console-bkt/policy", json={"mode": "custom", "policy": "{bad"}).status_code == 400
    assert c.put(f"{srv.curl}/api/buckets/console-bkt/policy", json={"mode": "private"}).status_code == 200
    assert requests.get(f"{srv.url}/console-bkt/pasta/arquivo%20%C3%A7.txt").status_code == 403
    assert c.put(f"{srv.curl}/api/buckets/console-bkt/lifecycle", json={"rules": [{"prefix": "logs/", "enabled": True, "expirationDays": 30}]}).status_code == 200
    assert s3.get_bucket_lifecycle_configuration(Bucket="console-bkt")["Rules"][0]["Expiration"]["Days"] == 30
    det = c.get(f"{srv.curl}/api/buckets/console-bkt").json()
    assert det["versioning"] == "Enabled" and det["lifecycle"][0]["prefix"] == "logs/"
    info = c.get(f"{srv.curl}/api/buckets/console-bkt/object", params={"key": "pasta/arquivo ç.txt"}).json()
    assert info["size"] == 8 and len(info["versions"]) == 1
    # Folder delete and forced bucket delete
    assert c.delete(f"{srv.curl}/api/buckets/console-bkt/prefix", params={"prefix": "pasta/"}).json()["deleted"] == 1
    assert c.delete(f"{srv.curl}/api/buckets/console-bkt").status_code == 409
    assert c.delete(f"{srv.curl}/api/buckets/console-bkt", params={"force": "true"}).status_code == 200
    assert err_code(s3.head_bucket, Bucket="console-bkt") in ("404", "NoSuchBucket")


def t_access_keys(srv, s3):
    c = console_session(srv)
    k = c.post(f"{srv.curl}/api/keys", json={"readOnly": True, "description": "leitura"}).json()
    ro = client(srv, ak=k["accessKey"], sk=k["secretKey"])
    assert ro.get_object(Bucket="alpha", Key="docs/hello.txt")["Body"].read().startswith(b"hello")
    assert err_code(ro.put_object, Bucket="alpha", Key="ro-write", Body=b"x") == "AccessDenied"
    assert err_code(ro.delete_object, Bucket="alpha", Key="docs/hello.txt") == "AccessDenied"
    assert err_code(ro.create_bucket, Bucket="ro-bucket") == "AccessDenied"
    rc = console_session(srv, k["accessKey"], k["secretKey"])
    assert rc.get(f"{srv.curl}/api/keys").status_code == 403
    assert rc.post(f"{srv.curl}/api/buckets", json={"name": "ro-made"}).status_code == 403
    w = c.post(f"{srv.curl}/api/keys", json={"readOnly": False}).json()
    rw = client(srv, ak=w["accessKey"], sk=w["secretKey"])
    rw.put_object(Bucket="alpha", Key="rw-write", Body=b"ok")
    keys = [x["accessKey"] for x in c.get(f"{srv.curl}/api/keys").json()]
    assert k["accessKey"] in keys and w["accessKey"] in keys
    assert c.delete(f"{srv.curl}/api/keys/{w['accessKey']}").status_code == 200
    assert err_code(rw.list_buckets) == "InvalidAccessKeyId"


def t_webhooks(srv, s3):
    received = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers["Content-Length"])
            received.append((self.headers.get("Authorization"), json.loads(self.rfile.read(n))))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    hs = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=hs.serve_forever, daemon=True).start()
    c = console_session(srv)
    s3.create_bucket(Bucket="hooks")
    r = c.put(f"{srv.curl}/api/buckets/hooks/webhooks", json={"webhooks": [
        {"url": f"http://127.0.0.1:{hs.server_port}/hook", "events": ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"], "prefix": "in/", "suffix": "", "token": "tok123"}]})
    assert r.status_code == 200, r.text
    s3.put_object(Bucket="hooks", Key="in/file.txt", Body=b"x")
    s3.put_object(Bucket="hooks", Key="out/ignored.txt", Body=b"x")
    s3.delete_object(Bucket="hooks", Key="in/file.txt")
    deadline = time.time() + 5
    while time.time() < deadline and len(received) < 2:
        time.sleep(0.1)
    time.sleep(0.3)
    hs.shutdown()
    names = [r[1]["Records"][0]["eventName"] for r in received]
    assert names == ["ObjectCreated:Put", "ObjectRemoved:Delete"], names
    assert received[0][0] == "Bearer tok123"
    assert received[0][1]["Records"][0]["s3"]["object"]["key"] == "in/file.txt"
    assert c.put(f"{srv.curl}/api/buckets/hooks/webhooks", json={"webhooks": [{"url": "ftp://x", "events": []}]}).status_code == 400


def t_restart(srv, s3, binary):
    """Data, keys and encryption survive a restart."""
    before = s3.get_object(Bucket="enc", Key="secret.bin")["Body"].read()
    srv.proc.terminate()
    srv.proc.wait(10)
    env = dict(os.environ, BOXSPACE_ROOT_USER=ROOT_USER, BOXSPACE_ROOT_PASSWORD=ROOT_PASS, BOXSPACE_SERVER_URL=srv.url, RUST_LOG="warn")
    srv.proc = subprocess.Popen([binary, "server", "--address", f"127.0.0.1:{srv.port}", "--console-address", f"127.0.0.1:{srv.cport}",
                                 os.path.join(srv.dir, "data")], env=env, stdout=srv.log, stderr=subprocess.STDOUT)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", srv.port), 0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    assert s3.get_object(Bucket="enc", Key="secret.bin")["Body"].read() == before
    assert s3.get_bucket_versioning(Bucket="ver")["Status"] == "Suspended"


TESTS = [t_buckets, t_objects, t_special_keys, t_listing, t_copy, t_multipart, t_presigned, t_versioning, t_tagging,
         t_policy, t_cors, t_encryption, t_lifecycle, t_auth, t_streaming, t_console, t_access_keys, t_webhooks]


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "target", "debug", "boxspace")
    srv = Server(os.path.abspath(binary))
    s3 = client(srv)
    failed = 0
    try:
        for t in TESTS + [lambda srv, s3: t_restart(srv, s3, os.path.abspath(binary))]:
            name = getattr(t, "__name__", "t_restart").replace("<lambda>", "t_restart")
            start = time.time()
            try:
                t(srv, s3)
                print(f"  ok    {name} ({time.time() - start:.1f}s)")
            except Exception:
                failed += 1
                print(f"  FAIL  {name}")
                traceback.print_exc()
    finally:
        srv.stop()
        if failed:
            print(f"\nserver log: {os.path.join(srv.dir, 'server.log')}")
        else:
            shutil.rmtree(srv.dir, ignore_errors=True)
    total = len(TESTS) + 1
    print(f"\n{total - failed}/{total} grupos de testes passaram")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()

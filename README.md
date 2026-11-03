# BoxSpace

Servidor de armazenamento de objetos compatível com a API S3, escrito em Rust. É um binário único com console web embutido. Ele roda com um disco ou com vários, protegendo os dados por espelhamento ou erasure coding, e pode replicar para outro servidor S3.

Ele funciona com qualquer cliente S3: AWS CLI, boto3, AWS SDKs (JavaScript, Java, Go, .NET…), rclone, s3cmd e outros.

## Início rápido

```bash
cargo build --release

export BOXSPACE_ROOT_USER=admin
export BOXSPACE_ROOT_PASSWORD='uma-senha-forte'
./target/release/boxspace server /caminho/para/dados
```

- API S3: `http://localhost:9000`
- Console web: `http://localhost:9001` (entre com o usuário e a senha root)

```bash
aws --endpoint-url http://localhost:9000 s3 mb s3://meu-bucket
aws --endpoint-url http://localhost:9000 s3 cp foto.jpg s3://meu-bucket/fotos/
```

```python
import boto3
s3 = boto3.client("s3", endpoint_url="http://localhost:9000",
                  aws_access_key_id="admin", aws_secret_access_key="uma-senha-forte",
                  region_name="us-east-1")
s3.upload_file("foto.jpg", "meu-bucket", "fotos/foto.jpg")
```

Para clientes que usam o estilo virtual-host por padrão (como o SDK JS v3), ative `forcePathStyle: true` ou defina `BOXSPACE_DOMAIN`.

### Com Docker

```bash
docker run -d --name boxspace \
  -p 9000:9000 -p 9001:9001 \
  -e BOXSPACE_ROOT_USER=admin \
  -e BOXSPACE_ROOT_PASSWORD='uma-senha-forte' \
  -e BOXSPACE_KMS_SECRET_KEY="$(openssl rand -base64 32)" \
  -v boxspace-data:/data \
  ghcr.io/diogenespetry/boxspace:latest
```

Guarde o valor de `BOXSPACE_KMS_SECRET_KEY` que você usou: os objetos criptografados só podem ser lidos com ele.

Com Docker Compose e quatro discos em erasure coding:

```yaml
services:
  boxspace:
    image: ghcr.io/diogenespetry/boxspace:latest
    command: ["server", "--address", ":9000", "--console-address", ":9001",
              "--redundancy", "erasure", "/disk1", "/disk2", "/disk3", "/disk4"]
    ports: ["9000:9000", "9001:9001"]
    environment:
      BOXSPACE_ROOT_USER: admin
      BOXSPACE_ROOT_PASSWORD: uma-senha-forte
      BOXSPACE_KMS_SECRET_KEY: cole-aqui-a-chave-base64
      BOXSPACE_SERVER_URL: https://s3.seudominio.com.br
      BOXSPACE_METRICS_TOKEN: um-token-para-o-prometheus
    volumes:
      - /mnt/disco1:/disk1
      - /mnt/disco2:/disk2
      - /mnt/disco3:/disk3
      - /mnt/disco4:/disk4
    restart: unless-stopped
```

Os diretórios montados precisam pertencer ao usuário 65532, que é o usuário da imagem (`chown -R 65532:65532 /mnt/disco*`).

A imagem roda como usuário sem privilégios, sobre a distroless da Google, tem `HEALTHCHECK` embutido e está disponível para amd64 e arm64. Ela é publicada automaticamente pelo GitHub Actions a cada push no `main` (tag `latest`) e a cada tag `v*` (por exemplo `v0.2.0` gera `0.2.0` e `0.2`).

## Discos e redundância

```
boxspace server [OPÇÕES] <DIRETÓRIO>...
```

| Discos | Modo padrão | O que tolera |
|---|---|---|
| 1 | `single` | Nada. Use replicação ou backup. |
| 2 ou mais | `mirror` | Perda de todos os discos menos um. Cada arquivo é gravado em todos os discos. |
| 3 ou mais, com `--redundancy erasure` | `erasure` | Perda de `--parity` discos (padrão: metade). Usa menos espaço que o espelhamento. |

Cada diretório deve ficar em um disco físico diferente. O modo e a quantidade de discos são fixados na primeira inicialização e gravados em `format.json`. A ordem dos diretórios precisa ser mantida nas próximas inicializações.

**Erasure coding.** Cada arquivo é dividido em blocos. Cada bloco vira *N − paridade* fragmentos de dados mais *paridade* fragmentos calculados com Reed-Solomon, um por disco. Qualquer conjunto de fragmentos de dados intactos reconstrói o bloco. Cada fragmento tem CRC32, então corrupção silenciosa (bitrot) é detectada na leitura e corrigida com a paridade. Com 4 discos e paridade 2, por exemplo, dois discos podem falhar e metade do espaço vai para proteção.

**Gravação com discos faltando.** No modo `mirror`, uma gravação é aceita se pelo menos um disco estiver online; as cópias que faltam são criadas pela verificação de integridade quando os discos voltam. No modo `erasure`, é preciso ter online pelo menos os discos de dados mais um.

**Quando um disco falha.** As leituras continuam a partir das cópias ou fragmentos restantes. O disco é marcado como offline e verificado a cada 10 segundos. Quando volta, a verificação de integridade reconstrói o que faltar.

**Troca de disco.** Pare o servidor, monte o disco novo, vazio, no mesmo diretório e inicie de novo. O BoxSpace detecta o disco novo e reconstrói os dados nele.

**Verificação de integridade.** A verificação confere cópias e fragmentos, repara o que estiver faltando ou corrompido e remove sobras de envios interrompidos. Ela roda ao iniciar após uma troca de disco, quando um disco volta, a cada `BOXSPACE_HEAL_INTERVAL` segundos e quando você pede no console. A "verificação completa" lê todos os dados e confere cada CRC.

**Metadados à prova de perda.** O índice (`meta.redb`) fica no primeiro disco. Cada versão de objeto também tem um `meta.json` gravado em todos os discos, e as configurações de buckets e chaves são copiadas para todos eles; as chaves vão cifradas com a chave mestra. Se o índice se perder, ele é reconstruído automaticamente na próxima inicialização.

## Arquivos legíveis no disco

Um bucket pode ser criado ou configurado com **arquivos legíveis no disco**. Com isso, a versão atual de cada objeto também aparece como arquivo comum, com o nome real, em `<primeiro disco>/<bucket>/<caminho>`. Assim você pode abrir, copiar ou fazer backup dos arquivos com qualquer ferramenta, sem o BoxSpace.

- Os arquivos são independentes dos dados guardados: editar um deles nunca altera o que o BoxSpace serve. Em btrfs ou XFS são clones copy-on-write (reflink), sem espaço extra; nos demais sistemas de arquivos são cópias e ocupam espaço adicional.
- São somente leitura. Alterações feitas direto no disco não voltam para o bucket.
- Exclusões, versões e marcadores de exclusão são refletidos: o arquivo mostra sempre a versão atual, e pastas vazias são removidas.
- Não pode ser usado junto com criptografia, porque arquivos cifrados não podem ser lidos fora do BoxSpace.
- Nomes que não podem virar caminhos seguros, como `..`, segmentos vazios ou nomes acima de 255 bytes, ficam só no bucket.
- Ao ativar em um bucket existente, os arquivos atuais são criados em segundo plano. Ao desativar, a pasta é removida.

## Replicação

No console, em **Configurações > Replicação**, cada bucket pode ter destinos S3: outro BoxSpace, AWS S3, Backblaze B2, Wasabi, MinIO etc. A replicação funciona assim:

- Objetos novos e alterados entram numa fila persistente e são enviados em segundo plano, com nova tentativa e espera crescente quando o destino está fora do ar.
- Objetos acima de 64 MB vão em multipart.
- Metadados, tipo, cabeçalhos e tags são copiados.
- Exclusões são replicadas se você marcar essa opção; exclusões feitas pelo lifecycle não são, como no S3.
- Ao adicionar um destino, os objetos existentes são enviados. O botão "Reenviar tudo" refaz o envio.
- Escritas que chegam por replicação não são replicadas de volta, então dois servidores podem replicar um para o outro.
- A secret key do destino é guardada cifrada com a chave mestra.

## Chaves de acesso e permissões

- **Root**: acesso total, inclusive ao gerenciamento de chaves e à auditoria.
- **Chaves de acesso** (criadas no console):
  - *Todos os buckets*: leitura e escrita (podem criar buckets e mudar configurações) ou somente leitura.
  - *Buckets específicos*: uma lista de buckets, com `*` como curinga (por exemplo `fotos-*`), cada um com leitura ou leitura e escrita. Essas chaves não criam buckets nem mudam configurações, e só veem os buckets da lista.
- **Anônimo**: só o que a bucket policy permitir.

As mudanças de permissão valem imediatamente, inclusive para sessões abertas no console.

## Monitoramento e auditoria

| Endpoint | Para quê |
|---|---|
| `GET /_boxspace/health/live` | Processo vivo (sempre 200) |
| `GET /_boxspace/health` | 200 se há discos suficientes para gravar, 503 se não; JSON com o estado dos discos |
| `GET /_boxspace/metrics` | Métricas Prometheus: requisições por operação e status, latência, bytes, objetos e bytes por bucket, discos, verificação de integridade e fila de replicação |

As métricas exigem `Authorization: Bearer <BOXSPACE_METRICS_TOKEN>`, a menos que `BOXSPACE_METRICS_PUBLIC=1`. O comando `boxspace healthcheck [URL]` sai com código 0 se o servidor estiver saudável; a imagem Docker o usa como `HEALTHCHECK`.

O **log de auditoria** grava uma linha JSON por requisição em `<primeiro disco>/.boxspace/audit/audit-AAAA-MM-DD.jsonl`, com hora, chave, operação, bucket, objeto, status, IP, bytes e duração. Ações do console e tentativas de login, inclusive as que falham, também entram. Os arquivos são apagados após `BOXSPACE_AUDIT_RETENTION_DAYS` dias. No console, a página **Auditoria** mostra e filtra os registros recentes.

## Configuração

```
boxspace server [--address :9000] [--console-address :9001]
                [--redundancy mirror|erasure] [--parity N] <DIRETÓRIO>...
boxspace healthcheck [URL]
```

| Variável | Padrão | Descrição |
|---|---|---|
| `BOXSPACE_ROOT_USER` | `boxspaceadmin` | Access key root (mín. 3 caracteres) |
| `BOXSPACE_ROOT_PASSWORD` | `boxspaceadmin` | Secret key root (mín. 8 caracteres) |
| `BOXSPACE_REGION` | `us-east-1` | Região informada aos clientes |
| `BOXSPACE_SERVER_URL` | `http://localhost:<porta>` | URL pública da API, usada nos links compartilhados pelo console |
| `BOXSPACE_DOMAIN` | — | Domínio para requisições virtual-host (`bucket.dominio`) |
| `BOXSPACE_KMS_SECRET_KEY` | gerada | Chave mestra da criptografia, em base64 (32 bytes) |
| `BOXSPACE_LIFECYCLE_INTERVAL` | `3600` | Segundos entre execuções do lifecycle |
| `BOXSPACE_HEAL_INTERVAL` | `86400` | Segundos entre verificações de integridade |
| `BOXSPACE_METRICS_TOKEN` | — | Token para `/_boxspace/metrics` |
| `BOXSPACE_METRICS_PUBLIC` | `0` | `1` para expor as métricas sem token |
| `BOXSPACE_AUDIT` | `1` | `0` para desligar o log de auditoria |
| `BOXSPACE_AUDIT_RETENTION_DAYS` | `30` | Dias de log de auditoria guardados |
| `BOXSPACE_TRUST_PROXY` | `0` | `1` para usar `X-Forwarded-For` como IP do cliente (atrás de proxy) |
| `BOXSPACE_HEALTH_URL` | `http://127.0.0.1:9000/_boxspace/health` | URL usada por `boxspace healthcheck` |
| `RUST_LOG` | `info` | `error`, `warn`, `info`, `debug` ou `trace` |

O servidor avisa no log quando está usando as credenciais padrão. Troque-as antes de expor o BoxSpace na rede.

### Chave mestra de criptografia

Se `BOXSPACE_KMS_SECRET_KEY` não estiver definida, o BoxSpace gera uma chave e a grava em `master.key`, com permissão `0600`, em todos os discos, para que a perda de um disco não leve a chave junto. Isso é prático em desenvolvimento. Em produção, gere uma chave (`openssl rand -base64 32`), passe-a pela variável de ambiente e guarde-a fora dos discos de dados. Sem a chave, os objetos criptografados, as chaves de acesso salvas nos discos e os segredos de replicação não podem ser lidos.

### TLS

O BoxSpace serve HTTP. Para HTTPS, coloque-o atrás de um proxy reverso (Caddy, nginx, Traefik), defina `BOXSPACE_SERVER_URL` com o endereço público `https://…` e, se quiser o IP real dos clientes na auditoria, `BOXSPACE_TRUST_PROXY=1`.

## Compatibilidade com a API S3

| Área | Operações suportadas |
|---|---|
| Buckets | ListBuckets, CreateBucket, DeleteBucket, HeadBucket, GetBucketLocation |
| Objetos | PutObject, GetObject (Range, condicionais, `response-*`), HeadObject, DeleteObject, DeleteObjects, CopyObject (COPY/REPLACE, condicionais da origem) |
| Listagem | ListObjects v1 e v2 (prefixo, delimitador, paginação, `encoding-type=url`), ListObjectVersions |
| Multipart | Create, UploadPart, UploadPartCopy, Complete, Abort, ListParts, ListMultipartUploads |
| Autenticação | SigV4 por cabeçalho, URLs pré-assinadas, payload em streaming assinado (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`) e com trailer (`STREAMING-UNSIGNED-PAYLOAD-TRAILER`, verificação de CRC32) |
| Integridade | Content-MD5, `x-amz-content-sha256`, `x-amz-checksum-crc32` |
| Versionamento | Enabled/Suspended, delete markers, leitura e exclusão por versão |
| Tags | Tags de objeto (inclusive `x-amz-tagging` no upload) e de bucket |
| Políticas | Bucket policy no formato JSON da AWS para acesso anônimo |
| CORS | Configuração por bucket, preflight `OPTIONS` e cabeçalhos nas respostas |
| Criptografia | SSE-S3 (AES-256-GCM) por objeto ou como padrão do bucket |
| Lifecycle | Expiração por dias ou data, versões não atuais, delete markers expirados, aborto de uploads incompletos; filtros por prefixo e tags |
| Escrita condicional | `If-None-Match: *` e `If-Match` no PutObject |
| ACL | Somente ACL privada; leitura de ACL retorna o dono com FULL_CONTROL |

### Não suportado

O servidor responde `NotImplemented` para estes recursos:

- Assinatura V2 (SigV2)
- SSE-C e SSE-KMS
- Object Lock, retenção e legal hold
- Configuração de replicação, website, logging, inventário, analytics e transições pela API S3 (a replicação é configurada no console)
- ACLs públicas e grants (use bucket policy)
- Upload via formulário POST
- Notificações pela API S3 (`PutBucketNotificationConfiguration`); configure webhooks no console
- Leitura de partes individuais com `partNumber` maior que 1

Políticas com `Condition`, `NotAction`, `NotResource` ou `NotPrincipal` são aceitas, mas, por segurança, esses `Allow` são ignorados e esses `Deny` são aplicados sem condição.

## Console web

O console roda numa porta separada e oferece:

- Buckets: criar, inclusive com arquivos legíveis no disco, excluir (inclusive com conteúdo) e ver uso
- Navegação por pastas, busca por nome, envio por arrastar e soltar (inclusive de pastas), seleção múltipla para excluir ou baixar em ZIP
- Pré-visualização de imagens, PDF, vídeo, áudio e texto
- Links de compartilhamento com validade (URLs pré-assinadas)
- Detalhes do objeto, metadados, tags, local no disco e histórico de versões
- Configuração de versionamento, arquivos legíveis, criptografia, acesso público, replicação, limpeza automática e webhooks
- Chaves de acesso com permissões por bucket (root)
- Auditoria com filtros (root)
- Página do servidor: discos, espaço livre, verificação de integridade, monitoramento e exemplos de conexão

As sessões usam cookie `HttpOnly` com `SameSite=Strict`. As escritas exigem um cabeçalho anti-CSRF. As páginas são servidas com CSP e `X-Frame-Options: DENY`, e as pré-visualizações com `CSP: sandbox`; HTML nunca é renderizado, só mostrado como texto.

## Webhooks

Os eventos são enviados como `POST` com JSON no formato de notificação do S3 (`Records[].eventName`, `s3.bucket.name`, `s3.object.key`, …). Cada webhook tem filtro por tipo de evento (criação, exclusão ou ambos) e por prefixo, e aceita um token opcional, enviado como `Authorization: Bearer`. Cada entrega é tentada até 3 vezes.

## Armazenamento em disco

```
<disco>/.boxspace/
  format.json            instalação, índice do disco e modo de redundância
  objects/<bucket>/…/    uma pasta por versão ou parte: meta.json + data (ou shard)
  sys/                   configurações de buckets e chaves (cifradas)
  master.key             chave mestra (se não vier do ambiente)
  tmp/                   gravações em andamento (limpo na inicialização)
  meta.redb              índice de metadados (só no primeiro disco)
  audit/                 log de auditoria (só no primeiro disco)
<primeiro disco>/<bucket>/  arquivos legíveis, nos buckets que usam essa opção
```

Cada objeto é gravado em arquivos temporários, sincronizado com o disco e só então movido para o lugar e registrado. Por isso, uma queda no meio de um upload não corrompe o objeto anterior. Uploads multipart não são copiados ao final: o objeto passa a referenciar as partes já gravadas, então concluir um upload de 50 GB é instantâneo.

## Desenvolvimento

```bash
cargo test                                      # testes unitários
pip install boto3 requests
cargo build
python3 tests/compat_test.py                    # compatibilidade S3 com boto3
python3 tests/features_test.py                  # redundância, replicação, console…
```

Os testes de compatibilidade cobrem buckets, objetos, nomes com caracteres especiais, listagens paginadas, cópia, multipart, URLs pré-assinadas, versionamento, tags, políticas, CORS, criptografia, lifecycle, streaming assinado, o console, chaves de acesso, webhooks e reinício.

Os testes de recursos cobrem:

- Espelhamento com perda e troca de disco
- Erasure coding com perda de discos, bitrot e verificação completa
- Reconstrução do índice
- Arquivos legíveis
- Permissões por bucket
- Saúde, métricas e auditoria
- Replicação entre dois servidores, inclusive multipart e proteção contra laços
- Busca, ZIP, pré-visualização e exclusão em lote no console
- Desempenho da listagem com milhares de objetos

### Estrutura do código

| Módulo | Responsabilidade |
|---|---|
| `api.rs` | Roteamento e operações da API S3, saúde e métricas |
| `auth.rs` | Verificação SigV4, URLs pré-assinadas e permissões das chaves |
| `body.rs` | Leitura de corpos: simples, SHA-256 e aws-chunked |
| `disk.rs` | Conjunto de discos, formato e estado online/offline |
| `phys.rs` | Gravação e leitura físicas: single, mirror e erasure coding, verificação e reparo |
| `blob.rs` | Criptografia sobre a camada física e leitura de objetos multipart |
| `storage.rs` | Índice de metadados (redb), contadores e fila de replicação |
| `sidecar.rs` | `meta.json` e configurações em todos os discos, reconstrução do índice |
| `heal.rs` | Verificação de integridade, reparo e remoção de sobras |
| `view.rs` | Arquivos legíveis no disco |
| `replication.rs` | Fila, worker e cliente S3 da replicação |
| `listing.rs` | Listagens com prefixo, delimitador e marcadores |
| `ops.rs` | Operações compartilhadas entre API, console e lifecycle |
| `metrics.rs`, `audit.rs` | Métricas Prometheus e log de auditoria |
| `policy.rs`, `cors.rs`, `lifecycle.rs`, `events.rs`, `crypto.rs` | Recursos de bucket |
| `console.rs`, `zip.rs`, `console/index.html` | Console web |

## Licença

Apache-2.0. Veja `LICENSE`.

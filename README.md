# BoxSpace

Servidor de armazenamento de objetos compatível com a API S3, escrito em Rust. É um binário único, com console web embutido, e roda em um nó com disco local.

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

## Configuração

```
boxspace server [--address :9000] [--console-address :9001] <DIRETÓRIO>
```

| Variável | Padrão | Descrição |
|---|---|---|
| `BOXSPACE_ROOT_USER` | `boxspaceadmin` | Access key root (mín. 3 caracteres) |
| `BOXSPACE_ROOT_PASSWORD` | `boxspaceadmin` | Secret key root (mín. 8 caracteres) |
| `BOXSPACE_REGION` | `us-east-1` | Região informada aos clientes |
| `BOXSPACE_SERVER_URL` | `http://localhost:<porta>` | URL pública da API, usada nos links compartilhados pelo console |
| `BOXSPACE_DOMAIN` | — | Domínio para requisições virtual-host (`bucket.dominio`) |
| `BOXSPACE_KMS_SECRET_KEY` | gerada | Chave mestra da criptografia, em base64 (32 bytes) |
| `BOXSPACE_LIFECYCLE_INTERVAL` | `3600` | Intervalo, em segundos, entre execuções do lifecycle |
| `RUST_LOG` | `info` | `error`, `warn`, `info`, `debug` ou `trace` |

O servidor avisa no log quando está usando as credenciais padrão. Troque-as antes de expor o BoxSpace na rede.

### Chave mestra de criptografia

Se `BOXSPACE_KMS_SECRET_KEY` não estiver definida, o BoxSpace gera uma chave em `<dados>/.boxspace/master.key` com permissão `0600`. Isso é prático em desenvolvimento. Em produção, gere uma chave (`openssl rand -base64 32`) e passe-a pela variável de ambiente, guardando-a fora do disco de dados. Sem a chave, os objetos criptografados não podem ser lidos.

### TLS

O BoxSpace serve HTTP. Para HTTPS, coloque-o atrás de um proxy reverso (Caddy, nginx, Traefik) e defina `BOXSPACE_SERVER_URL` com o endereço público `https://…`.

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
- Replicação, website, logging, inventário, analytics e transições de classe de armazenamento
- ACLs públicas e grants (use bucket policy)
- Upload via formulário POST
- Notificações pela API S3 (`PutBucketNotificationConfiguration`); configure webhooks no console
- Leitura de partes individuais com `partNumber` maior que 1

Políticas com `Condition`, `NotAction`, `NotResource` ou `NotPrincipal` são aceitas, mas, por segurança, esses `Allow` são ignorados e esses `Deny` são aplicados sem condição.

## Modelo de acesso

- **Root**: acesso total, inclusive ao gerenciamento de chaves no console.
- **Chaves de acesso** (criadas no console): leitura e escrita, ou somente leitura. Chaves somente leitura não alteram nada pela API nem pelo console.
- **Anônimo**: só o que a bucket policy permitir.

## Console web

O console roda numa porta separada e oferece:

- Buckets: criar, excluir (inclusive com conteúdo) e ver uso
- Navegação por pastas, envio por arrastar e soltar (inclusive de pastas), download, exclusão de arquivos e pastas
- Links de compartilhamento com validade (URLs pré-assinadas)
- Detalhes do objeto, metadados, tags e histórico de versões
- Configuração de versionamento, criptografia, acesso público ou política personalizada, regras de limpeza automática e webhooks
- Chaves de acesso (somente root)
- Página do servidor com estatísticas e exemplos de conexão

As sessões usam cookie `HttpOnly` com `SameSite=Strict`. As escritas exigem um cabeçalho anti-CSRF, e as páginas são servidas com CSP e `X-Frame-Options: DENY`.

## Webhooks

Os eventos são enviados como `POST` com JSON no formato de notificação do S3 (`Records[].eventName`, `s3.bucket.name`, `s3.object.key`, …). Cada webhook tem filtro por tipo de evento (criação, exclusão ou ambos) e por prefixo, e aceita um token opcional, enviado como `Authorization: Bearer`. Cada entrega é tentada até 3 vezes.

## Armazenamento em disco

```
<dados>/.boxspace/
  meta.redb       metadados (buckets, versões, uploads, chaves)
  master.key      chave mestra (se não vier do ambiente)
  blobs/          conteúdo dos objetos
  uploads/        partes de uploads multipart em andamento
  tmp/            uploads em andamento (limpo na inicialização)
```

Os metadados ficam em [redb](https://github.com/cberner/redb), um banco embutido transacional. Cada objeto é gravado num arquivo temporário, sincronizado com o disco e só então movido para o lugar e registrado, então uma queda no meio de um upload não corrompe o objeto anterior.

## Desenvolvimento

```bash
cargo test                                   # testes unitários
pip install boto3 requests
cargo build && python3 tests/compat_test.py  # testes de compatibilidade com boto3
```

Os testes de compatibilidade sobem um servidor temporário e cobrem buckets, objetos, nomes com caracteres especiais, listagens paginadas, cópia, multipart, URLs pré-assinadas, versionamento, tags, políticas, CORS, criptografia, lifecycle, streaming assinado, o console, chaves de acesso, webhooks e reinício do servidor.

### Estrutura do código

| Módulo | Responsabilidade |
|---|---|
| `api.rs` | Roteamento e operações da API S3 |
| `auth.rs` | Verificação SigV4 e URLs pré-assinadas |
| `body.rs` | Leitura de corpos: simples, SHA-256 e aws-chunked |
| `blob.rs` | Escrita e leitura de dados, com criptografia |
| `storage.rs` | Metadados no redb |
| `listing.rs` | Listagens com prefixo, delimitador e marcadores |
| `ops.rs` | Operações compartilhadas entre API, console e lifecycle |
| `policy.rs`, `cors.rs`, `lifecycle.rs`, `events.rs`, `crypto.rs` | Recursos de bucket |
| `console.rs`, `console/index.html` | Console web |

## Licença

Apache-2.0. Veja `LICENSE`.

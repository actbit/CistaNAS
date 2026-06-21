# CistaNAS

> 🌐 English | [日本語](./README.ja.md)

Encrypted NAS application built with .NET 10 + ASP.NET Core + Blazor Interactive Server rendering.

Volume-level encryption (server-side AES-XTS / E2EE AES-256-GCM), multi-user key management, journaling, media streaming, WebDAV, and a Dokan.NET client.

## Features

- **Volume encryption** — Transparent sector-level encryption with AES-XTS (IEEE 1619). Unencrypted volumes can also be created
- **Chunk-based storage** — `volume.dat` is split into chunks and stored on S3/R2 etc., removing the need for local disk on the VPS. Supports both server-side encryption and E2EE
- **E2EE (End-to-End Encryption)** — Client-side AES-256-GCM chunk encryption. The server only ever holds encrypted data and cannot access plaintext
- **Multi-user key management** — Each user wraps the master key with an independent PBKDF2 → KEK. Password changes re-wrap only the target user's entry
- **Shared volumes** — Owners can grant/revoke access to other users, with group-level access control
- **Media streaming** — Video playback and photo preview in the browser. Regular volumes support HTTP Range seeking; E2EE volumes use chunk-wise Blob URL previews
- **3 client types** — Browser (Blazor + Web Crypto API), Windows (Dokan.NET virtual filesystem), WebDAV (rclone / RCX)
- **Journaling** — Crash recovery for write operations
- **WebDAV** — Direct access from external clients
- **REST API** — `/api/v1` provides volume, file, auth, E2EE, and streaming endpoints
- **Setup wizard** — Creates the admin user on first launch
- **Cloud-ready** — Containerized (Docker) + cloud storage (S3 / Azure Blob / GCS) + Kubernetes manifests

## Solution Structure

| Project | Role |
|---|---|
| `CistaNAS.AppHost` | .NET Aspire orchestration |
| `CistaNAS.Web` | Blazor WebUI + REST API + WebDAV (single process) |
| `CistaNAS.Client` | Dokan.NET Windows virtual filesystem client |
| `CistaNAS.ServiceDefaults` | Aspire shared settings (telemetry, health checks) |
| `CistaNAS.Tests` | xUnit tests |

## Storage Providers

The storage backend for metadata (volume headers, catalogs, journals) is swappable. User and group information is stored in a DB (SQLite / PostgreSQL).

### Volume data placement

| Storage mode | volume.dat location | Target |
|---|---|---|
| `local` (default) | Local disk | Optimal for AES-XTS random access |
| `chunk` | Split into chunks on S3/R2 | No local disk required; Range-capable streaming |

With `ChunkStorage: "auto"`, the system automatically switches to chunk mode when using a cloud storage provider such as S3/R2.

| Provider | Setting | Metadata backend |
|---|---|---|
| `local` (default) | `local` | Local filesystem (`DataRoot`) |
| S3 / MinIO | `s3` | AWS S3 or S3-compatible (MinIO / LocalStack) |
| Azure Blob | `azureblob` | Azure Blob Storage |
| GCS | `gcs` | Google Cloud Storage (ADC auth) |

## Architecture

```
Pages (Blazor) / API Endpoints / WebDAV Handler
  └ Request handling & response
Services
  └ Business logic
      VolumeService          Volume create/mount/lock/access control (Singleton)
      FileService            File CRUD/listing/chunk storage (Scoped)
      E2eeFileService        Catalog & chunk management for E2EE volumes (Scoped)
      StreamingTokenService  Short-lived token for media streaming (Singleton)
      JournalService         Journaling & recovery (Scoped)
      AuthService            Auth & JWT issuance (Scoped)
      AccountService         User management (Scoped) — wraps ASP.NET Core Identity
      GroupService           Group management (Scoped) — uses EF Core
      InvitationService      Invitation code management (Singleton)
Crypto / Volume / Journal
  └ Low-level implementation
      AesXtsStream           AES-XTS seekable stream (for local volume.dat)
      AesXtsTransform        AES-XTS buffer-level transform (for chunk encryption)
      ChunkEncryptor         Per-chunk AES-XTS encrypt/decrypt helper
      E2eeCrypto             AES-256-GCM chunk encryption (Client)
      PasswordHasher         PBKDF2-SHA256 password hashing
      KeyDerivation          KEK derivation (PBKDF2)
Storage
  └ Storage abstraction
      IStorageProvider       Metadata backend (local / S3 / Azure Blob / GCS)
      IChunkStore            Chunk-based object storage (for chunk mode)
      S3ChunkStore           Chunk store implementation delegating to IStorageProvider
Helpers
  └ MediaHelper             MIME type & media kind detection
```

## Prerequisites

- .NET 10 SDK
- Dokan driver (only if using the Dokan.NET client)

## Run

```bash
dotnet run --project CistaNAS.AppHost
```

On first launch you will be redirected to `/setup` to create the admin user.

### Launch with MinIO (S3-compatible storage)

Setting the `ENABLE_MINIO=true` environment variable makes Aspire start a MinIO container and automatically switch the webfrontend to the S3 backend. The default (unset) uses local storage with no production impact.

```bash
# Via environment variable
ENABLE_MINIO=true dotnet run --project CistaNAS.AppHost

# Or via command-line argument
dotnet run --project CistaNAS.AppHost -- --ENABLE_MINIO true
```

MinIO console: `http://localhost:9001` (credentials: `minioadmin` / `minioadmin`)

### Standalone launch (without Aspire)

```bash
dotnet run --project CistaNAS.Web
```

### Dokan.NET client

```bash
dotnet run --project CistaNAS.Client -- <serverUrl> <username> <password> <mountPoint> [volumeName]

# Example
dotnet run --project CistaNAS.Client -- https://localhost:5001 admin mypassword Z: my-e2ee-vol
```

## Configuration

Configure under the `CistaNas` section of `appsettings.json`.

```json
{
  "CistaNas": {
    "DataRoot": "data",
    "Database": {
      "Provider": "sqlite",
      "ConnectionString": null,
      "BucketOrContainer": null,
      "RegionOrConnectionString": null,
      "EndpointOverride": null,
      "BlobKey": "cista.db"
    },
    "Storage": {
      "Provider": "local",
      "BucketOrContainer": null,
      "RegionOrConnectionString": null,
      "EndpointOverride": null,
      "PathPrefix": null,
      "VolumeDataPath": null
    },
    "Jwt": {
      "Issuer": "CistaNAS",
      "Audience": "CistaNAS",
      "SigningKey": null,
      "AccessTokenMinutes": 60
    },
    "Auth": {
      "Pbkdf2Iterations": 210000
    },
    "Volume": {
      "SectorSize": 4096,
      "KdfIterations": 600000,
      "DefaultEncryptionMode": "server",
      "E2eeChunkSize": 1048576,
      "ChunkStorage": "local",
      "ServerChunkSize": 4194304
    }
  }
}
```

| Key | Description |
|---|---|
| `DataRoot` | Data location in local mode |
| `Database:Provider` | `"sqlite"` / `"postgresql"` / `"s3"` / `"azureblob"` / `"gcs"` |
| `Database:ConnectionString` | PostgreSQL: connection string. SQLite: file path (null → `DataRoot/cista.db`) |
| `Database:BucketOrContainer` | S3/Blob/GCS: bucket/container name |
| `Database:RegionOrConnectionString` | S3: region, Azure: connection string |
| `Database:EndpointOverride` | S3: endpoint override (for MinIO) |
| `Database:BlobKey` | DB file path within object storage (default `cista.db`) |
| `Storage:Provider` | `"local"` / `"s3"` / `"azureblob"` / `"gcs"` |
| `Storage:BucketOrContainer` | S3: bucket name, Azure: container name, GCS: bucket name |
| `Storage:RegionOrConnectionString` | S3: region, Azure: connection string |
| `Storage:EndpointOverride` | S3: endpoint override (for MinIO / LocalStack) |
| `Storage:PathPrefix` | Path prefix within the bucket/container |
| `Storage:VolumeDataPath` | Local path for volume.dat (PV mount path on K8s). Defaults to `DataRoot` |
| `Jwt:SigningKey` | Randomly generated per launch if unset (tokens invalidated on restart) |
| `Jwt:AccessTokenMinutes` | Access token lifetime in minutes |
| `Auth:Pbkdf2Iterations` | Password hash iterations (default 600,000) |
| `Volume:SectorSize` | AES-XTS sector size (multiple of 16) |
| `Volume:KdfIterations` | PBKDF2 iterations for KEK derivation (default 600,000) |
| `Volume:DefaultEncryptionMode` | Default encryption mode (`server` / `e2ee` / `none`) |
| `Volume:E2eeChunkSize` | E2EE chunk size in bytes (default 1 MiB) |
| `Volume:ChunkStorage` | Chunk storage mode (`local` = always volume.dat / `auto` = auto-chunk on S3) |
| `Volume:ServerChunkSize` | Server-side chunk size in chunk mode (default 4 MiB) |

## How Encryption Works

### Server-side encryption (AES-XTS)

```
Login password
  └ PBKDF2(password, SHA256(username) || salt, iterations) → KEK
      └ AES-256-GCM unwraps the master key
          └ Master key (64B) encrypts/decrypts AES-XTS volume data
```

#### Local mode (volume.dat)

An AES-XTS stream transparently seeks and writes encrypted data directly to volume.dat.

#### Chunk mode (S3/R2)

```
Upload → Split file into chunks (4 MiB default)
       → Encrypt each chunk with AES-XTS (nonce = chunkIndex × sectorsPerChunk)
       → IChunkStore → S3 PUT "{volume}/chunks/{file}/{index}"

Download → S3 GET → ChunkedReadStream (Seekable + Range support)
         → Lazy fetch + per-chunk decryption (only one chunk held in memory)
```

- Cross-chunk nonce uniqueness: `firstSectorIndex = chunkIndex × (chunkSize / sectorSize)`
- Sector indices never collide across the whole volume, so this is compatible with stream mode
- For E2EE volumes in chunk mode, the encrypted blob is stored on S3 as-is (no server-side encryption needed)

### E2EE (End-to-End Encryption)

```
User password
  └ PBKDF2-SHA256(password, SHA256(username) || salt, 310000) → KEK (32B)
      └ AES-256-GCM wrap/unwrap of the master key
          └ Master key (32B) is generated and held only on the client

Per file:
  HKDF-SHA256(masterKey, fileSalt, "cista-file-key") → FileKey (32B)
    └ Per chunk:
        Nonce = HMAC-SHA256(FileKey, fileSalt || chunkIndex)[0:12]
        AES-256-GCM(plaintext, nonce, AAD=chunkIndex) → Ciphertext + Tag
```

#### Chunk format

```
Chunk 0: [FileSalt (16B)] [Ciphertext] [Tag (16B)]
Chunk N: [Ciphertext] [Tag (16B)]
```

- Chunk size: 1 MiB (configurable)
- Streaming-friendly: read/write per chunk
- Filenames are also encrypted with AES-256-GCM (Base64 encoded)

#### E2EE security properties

- **Master key is generated only on the client** and never sent to the server
- **fileSalt is included in nonce derivation** — reduces predictability if FileKey leaks
- **Authenticated encryption** — integrity guaranteed via AES-256-GCM / ChaCha20-Poly1305
- **Safe even on server compromise** — only encrypted data and wrapped keys can leak
- **Unrecoverable if password is lost** — keys exist only on the client

## Media Streaming

Supports preview of video, audio, and images in the browser.

### Regular volumes

1. After authentication, a short-lived streaming token (60s) is issued
2. The token-bearing URL is set as the `src` of `video`/`audio`/`img`
3. Native streaming with seek support via HTTP Range requests

### E2EE volumes

1. Chunks are downloaded and decrypted sequentially
2. A Blob URL is generated and set as the `src` of `video`/`audio`/`img`

Supported formats: jpg, png, gif, webp, bmp, svg, avif, tiff, mp4, webm, mkv, mov, mp3, wav, ogg, aac, flac, opus, etc.

## API Endpoints

```
# Auth
POST   /api/v1/auth/setup             Create initial admin
POST   /api/v1/auth/login             Login
POST   /api/v1/auth/change-password   Change password

# Volumes
POST   /api/v1/volumes/               Create volume
GET    /api/v1/volumes/               List volumes
POST   /api/v1/volumes/{name}/mount   Mount
POST   /api/v1/volumes/{name}/lock    Lock
POST   /api/v1/volumes/{name}/grant   Grant access
POST   /api/v1/volumes/{name}/revoke  Revoke access

# Files
GET    /api/v1/files/{volume}/                         List files
POST   /api/v1/files/{volume}/{*path}                  Upload
GET    /api/v1/files/{volume}/{*path}                  Download
DELETE /api/v1/files/{volume}/{*path}                  Delete

# Media streaming
POST   /api/v1/stream/token                          Issue token
GET    /api/v1/stream/{volume}/{*path}?token=xxx      Stream

# E2EE
POST   /api/v1/e2ee/create-volume                     Create E2EE volume
POST   /api/v1/e2ee/{volume}/mount                    Mount
POST   /api/v1/e2ee/{volume}/create-file              Create file entry
POST   /api/v1/e2ee/{volume}/upload-chunk/{fileId}/{index}   Upload chunk
GET    /api/v1/e2ee/{volume}/download-chunk/{fileId}/{index}  Download chunk
PATCH  /api/v1/e2ee/{volume}/finalize-file/{fileId}           Finalize upload
DELETE /api/v1/e2ee/{volume}/files/{fileId}                   Delete file
GET    /api/v1/e2ee/{volume}/files                           List files
POST   /api/v1/e2ee/{volume}/add-wrapped-key                 Add shared key

# Groups
GET    /api/v1/groups/                                List groups
POST   /api/v1/groups/                                Create group
DELETE /api/v1/groups/{name}                          Delete group
POST   /api/v1/groups/{name}/members                  Add member
DELETE /api/v1/groups/{name}/members/{username}       Remove member
```

## WebDAV Access

WebDAV clients access `https://<host>/dav/<volume-name>/`.

Both Basic auth and JWT are supported.

WebDAV for E2EE volumes transfers encrypted filenames and encrypted blobs as-is. It can also be combined with external encryption tools (e.g. rclone crypt).

## Security Measures

- **Auth timing-attack mitigation** — Response time is uniform regardless of user existence (dummy PBKDF2 computation)
- **Path sanitizer** — Prevents directory traversal (both API and WebDAV)
- **Rate limiting** — Auth endpoints 10 req/min/IP, overall API 100 req/min/IP
- **Auth lockout** — Locks for 15 minutes after 5 failures (PBKDF2 600,000 iterations)
- **Security headers** — CSP, HSTS, X-Content-Type-Options, X-Frame-Options, etc.
- **JWT signing key** — Must be ≥ 32 bytes in production (randomly generated in dev)
- **Streaming tokens** — 60s short-lived, URL-based access, max 10,000 tokens
- **Error messages** — No credential information leakage (details only in security logs)
- **Kestrel** — Request body limit 10 GiB, header timeout 30s
- **Key zeroing** — In-memory keys (master key, KEK) are wiped with `CryptographicOperations.ZeroMemory`

## Docker

```bash
# Build image
docker build -t cistanas .

# Launch in local mode
docker compose up

# Launch in S3 (MinIO) mode
docker compose --profile s3 -f docker-compose.yml -f docker-compose.s3.yml up
```

### Environment variables

| Variable | Description |
|---|---|
| `CistaNas__Database__Provider` | DB provider (`sqlite` / `postgresql` / `s3` / `azureblob` / `gcs`) |
| `CistaNas__Database__ConnectionString` | PostgreSQL: connection string |
| `CistaNas__Storage__Provider` | Storage provider (`local` / `s3` / `azureblob` / `gcs`) |
| `CistaNas__Storage__BucketOrContainer` | Bucket/container name |
| `CistaNas__Storage__RegionOrConnectionString` | S3: region, Azure: connection string |
| `CistaNas__Storage__EndpointOverride` | S3: endpoint URL for MinIO etc. |
| `CistaNas__Storage__VolumeDataPath` | Local path for volume.dat |
| `CistaNas__Volume__ChunkStorage` | `local` or `auto` (auto-chunk on S3) |
| `CistaNas__Volume__ServerChunkSize` | Server-side chunk size (bytes) |
| `CistaNas__Jwt__SigningKey` | JWT signing key (Base64) |
| `CistaNas__Auth__DefaultAdminPassword` | Initial admin password |

## Kubernetes

Deployable to each cloud via Kustomize overlays.

```bash
# AWS EKS
kubectl apply -k deploy/k8s/overlays/aws

# Azure AKS
kubectl apply -k deploy/k8s/overlays/azure

# Google GKE
kubectl apply -k deploy/k8s/overlays/gcp
```

Set up Secrets before deploying.

```bash
kubectl create secret generic cistanas-secrets \
  --from-literal=CistaNas__Jwt__SigningKey=<base64-32-byte-key> \
  --from-literal=CistaNas__Storage__BucketOrContainer=<bucket-name> \
  -n cistanas
```

Overlay configuration:

| Overlay | PVC storage class | Storage provider | Ingress |
|---|---|---|---|
| `aws` | `gp3` (20Gi) | S3 | ALB |
| `azure` | `managed-premium` (20Gi) | Azure Blob | Application Gateway |
| `gcp` | `pd-ssd` (20Gi) | GCS | GCE (static IP) |

## Tests

```bash
dotnet test
```

Includes encryption round-trip, E2EE chunk encrypt/decrypt, file operations, auth, WebDAV, volume lifecycle, path sanitization, streaming tokens, etc.

## License

MIT

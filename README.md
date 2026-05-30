# CistaNAS

暗号化 NAS アプリケーション。.NET 10 + ASP.NET Core + Blazor Interactive Server rendering で構築。

ボリューム単位の暗号化（サーバー暗号化 AES-XTS / E2EE AES-256-GCM）、マルチユーザー鍵管理、ジャーナリング、メディアストリーミング、WebDAV、Dokan.NET クライアント対応。

## 機能

- **ボリューム暗号化** — AES-XTS (IEEE 1619) によるセクタ単位の透過暗号化。暗号化なしのボリュームも作成可能
- **チャンクベースストレージ** — volume.dat を S3/R2 等にチャンク分割保存。VPS のローカルディスクを不要に。サーバー暗号化・E2EE 両対応
- **E2EE（エンドツーエンド暗号化）** — クライアント側 AES-256-GCM チャンク暗号化。サーバーは暗号化済みデータのみを保持し、平文にアクセス不可
- **マルチユーザー鍵管理** — ユーザーごとに独立した PBKDF2 → KEK でマスターキーをラップ。パスワード変更時は対象ユーザーのエントリのみ再ラップ
- **共有ボリューム** — オーナーが他ユーザーにアクセス権を付与・取り消し可能。グループ単位のアクセス制御にも対応
- **メディアストリーミング** — ブラウザでの動画再生・写真プレビュー。通常ボリュームは HTTP Range 要求でシーク対応、E2EE ボリュームはチャンク単位の Blob URL プレビュー
- **3 クライアント対応** — ブラウザ (Blazor + Web Crypto API)、Windows (Dokan.NET 仮想ファイルシステム)、WebDAV (rclone / RCX)
- **ジャーナリング** — 書き込み操作のクラッシュリカバリ
- **WebDAV** — 外部クライアントから直接アクセス可能
- **REST API** — `/api/v1` にボリューム・ファイル・認証・E2EE・ストリーミングエンドポイントを提供
- **セットアップウィザード** — 初回起動時に管理者ユーザーを作成
- **クラウド対応** — コンテナ化（Docker）+ クラウドストレージ（S3 / Azure Blob / GCS）+ Kubernetes マニフェスト

## ソリューション構成

| プロジェクト | 役割 |
|---|---|
| `CistaNAS.AppHost` | .NET Aspire オーケストレーション |
| `CistaNAS.Web` | Blazor WebUI + REST API + WebDAV（単一プロセス） |
| `CistaNAS.Client` | Dokan.NET Windows 仮想ファイルシステムクライアント |
| `CistaNAS.ServiceDefaults` | Aspire 共通設定（テレメトリ・ヘルスチェック） |
| `CistaNAS.Tests` | xUnit テスト (181 tests) |

## ストレージプロバイダ

メタデータ（ボリュームヘッダ、カタログ、ジャーナル）の保存先を切り替え可能。ユーザー・グループ情報は DB（SQLite / PostgreSQL）に保存。

### ボリュームデータの配置

| ストレージモード | volume.dat の配置 | 対象 |
|---|---|---|
| `local`（デフォルト） | ローカルディスク | AES-XTS ランダムアクセスに最適 |
| `chunk` | S3/R2 にチャンク分割保存 | VPS のローカルディスク不要。Range 対応ストリーミング |

`ChunkStorage: "auto"` 設定時は、S3/R2 等のクラウドストレージプロバイダ使用時に自動的にチャンクモードに切り替わる。

| プロバイダ | 設定値 | メタデータ保存先 |
|---|---|---|
| `local`（デフォルト） | `local` | ローカルファイルシステム（`DataRoot`） |
| S3 / MinIO | `s3` | AWS S3 または S3 互換（MinIO / LocalStack） |
| Azure Blob | `azureblob` | Azure Blob Storage |
| GCS | `gcs` | Google Cloud Storage（ADC 認証） |

## アーキテクチャ

```
Pages (Blazor) / API Endpoints / WebDAV Handler
  └ リクエスト受付・レスポンス返却
Services
  └ ビジネスロジック
      VolumeService          ボリューム作成・マウント・ロック・アクセス管理 (Singleton)
      FileService            ファイル CRUD・一覧・チャンクストレージ対応 (Scoped)
      E2eeFileService        E2EE ボリュームのカタログ・チャンク管理 (Scoped)
      StreamingTokenService  メディアストリーミング用短命トークン (Singleton)
      JournalService         ジャーナル記録・復旧 (Scoped)
      AuthService            認証・JWT 発行 (Scoped)
      AccountService         ユーザー管理 (Scoped) — ASP.NET Core Identity ラップ
      GroupService           グループ管理 (Scoped) — EF Core 使用
      InvitationService      招待コード管理 (Singleton)
Crypto / Volume / Journal
  └ 低レベル実装
      AesXtsStream           AES-XTS seekable ストリーム（ローカル volume.dat 用）
      AesXtsTransform        AES-XTS バッファ単位変換（チャンク暗号化用）
      ChunkEncryptor         チャンク単位 AES-XTS 暗号化/復号ヘルパー
      E2eeCrypto             AES-256-GCM チャンク暗号化 (Client)
      PasswordHasher         PBKDF2-SHA256 パスワードハッシュ
      KeyDerivation          KEK 導出 (PBKDF2)
Storage
  └ ストレージ抽象
      IStorageProvider       メタデータ保存先（local / S3 / Azure Blob / GCS）
      IChunkStore            チャンクベースオブジェクトストレージ（チャンクモード用）
      S3ChunkStore           IStorageProvider に委譲するチャンクストア実装
Helpers
  └ MediaHelper             MIMEタイプ判定・メディア種別判定
```

## 前提

- .NET 10 SDK
- Dokan ドライバ（Dokan.NET クライアントを使用する場合）

## 実行

```bash
dotnet run --project CistaNAS.AppHost
```

初回起動時は `/setup` にリダイレクトされ、管理者ユーザーの作成を求められる。

### 個別起動（Aspire なし）

```bash
dotnet run --project CistaNAS.Web
```

### Dokan.NET クライアント

```bash
dotnet run --project CistaNAS.Client -- <serverUrl> <username> <password> <mountPoint> [volumeName]

# 例
dotnet run --project CistaNAS.Client -- https://localhost:5001 admin mypassword Z: my-e2ee-vol
```

## 設定

`appsettings.json` の `CistaNas` セクションで設定する。

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

| 項目 | 説明 |
|---|---|
| `DataRoot` | ローカルモード時のデータ保存先 |
| `Database:Provider` | `"sqlite"` / `"postgresql"` / `"s3"` / `"azureblob"` / `"gcs"` |
| `Database:ConnectionString` | PostgreSQL: 接続文字列。SQLite: ファイルパス（null なら `DataRoot/cista.db`） |
| `Database:BucketOrContainer` | S3/Blob/GCS: バケット/コンテナ名 |
| `Database:RegionOrConnectionString` | S3: リージョン、Azure: 接続文字列 |
| `Database:EndpointOverride` | S3: エンドポイント上書き（MinIO 用） |
| `Database:BlobKey` | オブジェクトストレージ内の DB ファイルパス（デフォルト `cista.db`） |
| `Storage:Provider` | `"local"` / `"s3"` / `"azureblob"` / `"gcs"` |
| `Storage:BucketOrContainer` | S3: バケット名、Azure: コンテナ名、GCS: バケット名 |
| `Storage:RegionOrConnectionString` | S3: リージョン、Azure: 接続文字列 |
| `Storage:EndpointOverride` | S3: エンドポイント上書き（MinIO / LocalStack 用） |
| `Storage:PathPrefix` | バケット/コンテナ内のパスプレフィックス |
| `Storage:VolumeDataPath` | volume.dat のローカルパス（K8s では PV マウントパス）。未設定時は `DataRoot` |
| `Jwt:SigningKey` | 未設定時は起動ごとにランダム生成（再起動でトークン失効） |
| `Jwt:AccessTokenMinutes` | アクセストークンの有効期限（分） |
| `Auth:Pbkdf2Iterations` | パスワードハッシュの反復回数（デフォルト 600,000） |
| `Volume:SectorSize` | AES-XTS のセクタサイズ（16 の倍数） |
| `Volume:KdfIterations` | KEK 導出の PBKDF2 反復回数（デフォルト 600,000） |
| `Volume:DefaultEncryptionMode` | デフォルト暗号化モード（`server` / `e2ee` / `none`） |
| `Volume:E2eeChunkSize` | E2EE チャンクサイズ（バイト、デフォルト 1 MiB） |
| `Volume:ChunkStorage` | チャンクストレージモード（`local` = 常に volume.dat / `auto` = S3 使用時に自動チャンク） |
| `Volume:ServerChunkSize` | チャンクモード時のサーバー側チャンクサイズ（バイト、デフォルト 4 MiB） |

## 暗号化の仕組み

### サーバー暗号化（AES-XTS）

```
ログインパスワード
  └ PBKDF2(password, SHA256(username) || salt, iterations) → KEK
      └ AES-256-GCM でマスターキーをアンラップ
          └ マスターキー (64B) で AES-XTS ボリュームデータを暗号/復号
```

#### ローカルモード（volume.dat）

AES-XTS Stream を seekable に透過し、volume.dat に直接暗号化データを書き込む。

#### チャンクモード（S3/R2）

```
Upload → ファイルをチャンク分割（4 MiB デフォルト）
       → 各チャンクを AES-XTS で暗号化（nonce = chunkIndex × sectorsPerChunk）
       → IChunkStore → S3 PUT "{volume}/chunks/{file}/{index}"

Download → S3 GET → ChunkedReadStream（Seekable + Range 対応）
         → 遅延取得 + チャンク単位復号（1チャンク分のみメモリに保持）
```

- チャンク間の nonce 一意性: `firstSectorIndex = chunkIndex × (chunkSize / sectorSize)`
- ボリューム全体でセクタインデックスが重複しないため、ストリームモードと互換
- E2EE ボリュームのチャンクモードでは暗号化済み blob をそのまま S3 に保存（サーバー側暗号化不要）

### E2EE（エンドツーエンド暗号化）

```
ユーザーパスワード
  └ PBKDF2-SHA256(password, SHA256(username) || salt, 310000) → KEK (32B)
      └ AES-256-GCM でマスターキーを wrap/unwrap
          └ マスターキー (32B) はクライアント側でのみ生成・保持

ファイルごと:
  HKDF-SHA256(masterKey, fileSalt, "cista-file-key") → FileKey (32B)
    └ チャンクごと:
        Nonce = SHA-256(FileKey || chunkIndex)[0:12]  (決定論的)
        AES-256-GCM(plaintext, nonce, AAD=chunkIndex) → Ciphertext + Tag
```

#### チャンク形式

```
チャンク 0: [FileSalt (16B)] [Ciphertext] [Tag (16B)]
チャンク N: [Ciphertext] [Tag (16B)]
```

- チャンクサイズ: 1 MiB（設定可能）
- ストリーミング対応: チャンク単位で読み書き可能
- ファイル名も AES-256-GCM で暗号化（Base64 エンコード）

#### E2EE のセキュリティ特性

- マスターキーは**クライアントでのみ生成**され、サーバーには送信されない
- サーバーが保持するのは KEK でラップ済みのマスターキーのみ
- サーバー侵害でも暗号化済みデータとラップ済み鍵しか漏洩しない
- パスワード紛失時はデータの復旧が不可能

## メディアストリーミング

ブラウザでの動画・音声・画像のプレビューに対応。

### 通常ボリューム

1. 認証後に短命ストリーミングトークン（60秒有効）を発行
2. トークン付き URL を `video`/`audio`/`img` の `src` に設定
3. HTTP Range 要求でシーク対応のネイティブストリーミング

### E2EE ボリューム

1. チャンクを順次ダウンロード・復号
2. Blob URL を生成して `video`/`audio`/`img` の `src` に設定

対応形式: jpg, png, gif, webp, bmp, svg, avif, tiff, mp4, webm, mkv, mov, mp3, wav, ogg, aac, flac, opus 等

## API エンドポイント

```
# 認証
POST   /api/v1/auth/setup             初期管理者作成
POST   /api/v1/auth/login             ログイン
POST   /api/v1/auth/change-password   パスワード変更

# ボリューム
POST   /api/v1/volumes/               ボリューム作成
GET    /api/v1/volumes/               ボリューム一覧
POST   /api/v1/volumes/{name}/mount   マウント
POST   /api/v1/volumes/{name}/lock    ロック
POST   /api/v1/volumes/{name}/grant   アクセス権付与
POST   /api/v1/volumes/{name}/revoke  アクセス権剥奪

# ファイル
GET    /api/v1/files/{volume}/                         ファイル一覧
POST   /api/v1/files/{volume}/{*path}                  アップロード
GET    /api/v1/files/{volume}/{*path}                  ダウンロード
DELETE /api/v1/files/{volume}/{*path}                  削除

# メディアストリーミング
POST   /api/v1/stream/token                          トークン発行
GET    /api/v1/stream/{volume}/{*path}?token=xxx      ストリーミング

# E2EE
POST   /api/v1/e2ee/create-volume                     E2EE ボリューム作成
POST   /api/v1/e2ee/{volume}/mount                    マウント
POST   /api/v1/e2ee/{volume}/create-file              ファイルエントリ作成
POST   /api/v1/e2ee/{volume}/upload-chunk/{fileId}/{index}   チャンクアップロード
GET    /api/v1/e2ee/{volume}/download-chunk/{fileId}/{index}  チャンクダウンロード
PATCH  /api/v1/e2ee/{volume}/finalize-file/{fileId}           アップロード確定
DELETE /api/v1/e2ee/{volume}/files/{fileId}                   ファイル削除
GET    /api/v1/e2ee/{volume}/files                           ファイル一覧
POST   /api/v1/e2ee/{volume}/add-wrapped-key                 共有鍵追加

# グループ
GET    /api/v1/groups/                                グループ一覧
POST   /api/v1/groups/                                グループ作成
DELETE /api/v1/groups/{name}                          グループ削除
POST   /api/v1/groups/{name}/members                  メンバー追加
DELETE /api/v1/groups/{name}/members/{username}       メンバー削除
```

## WebDAV アクセス

WebDAV クライアントから `https://<host>/dav/<volume-name>/` にアクセスする。

Basic 認証と JWT の両方に対応。

E2EE ボリュームの WebDAV は暗号化済みファイル名と暗号化済み blob をそのまま転送する。外部暗号化ツール（rclone crypt 等）との併用も可能。

## セキュリティ対策

- パスサニタイザによるディレクトリトラバーサル防止（API・WebDAV 両対応）
- レート制限: 認証エンドポイント 10 req/min/IP、API 全体 100 req/min/IP
- セキュリティヘッダ: CSP, HSTS, X-Content-Type-Options 等
- JWT 署名鍵の本番環境必須化
- ストリーミングトークン: 60秒有効・短命・URL ベースアクセス用
- 資格情報のエラーメッセージに情報漏洩なし（セキュリティログのみ）
- Kestrel リクエストボディ上限 2 GiB、ヘッダタイムアウト 30 秒

## Docker

```bash
# イメージビルド
docker build -t cistanas .

# ローカルモードで起動
docker compose up

# S3 (MinIO) モードで起動
docker compose --profile s3 -f docker-compose.yml -f docker-compose.s3.yml up
```

### 環境変数

| 変数 | 説明 |
|---|---|
| `CistaNas__Database__Provider` | DB プロバイダ（`sqlite` / `postgresql` / `s3` / `azureblob` / `gcs`） |
| `CistaNas__Database__ConnectionString` | PostgreSQL: 接続文字列 |
| `CistaNas__Storage__Provider` | ストレージプロバイダ（`local` / `s3` / `azureblob` / `gcs`） |
| `CistaNas__Storage__BucketOrContainer` | バケット/コンテナ名 |
| `CistaNas__Storage__RegionOrConnectionString` | S3: リージョン、Azure: 接続文字列 |
| `CistaNas__Storage__EndpointOverride` | S3: MinIO 等のエンドポイント URL |
| `CistaNas__Storage__VolumeDataPath` | volume.dat のローカルパス |
| `CistaNas__Volume__ChunkStorage` | `local` または `auto`（S3 使用時に自動チャンク） |
| `CistaNas__Volume__ServerChunkSize` | サーバー側チャンクサイズ（バイト） |
| `CistaNas__Jwt__SigningKey` | JWT 署名鍵（Base64） |
| `CistaNas__Auth__DefaultAdminPassword` | 初期管理者パスワード |

## Kubernetes

Kustomize overlay で各クラウドにデプロイ可能。

```bash
# AWS EKS
kubectl apply -k deploy/k8s/overlays/aws

# Azure AKS
kubectl apply -k deploy/k8s/overlays/azure

# Google GKE
kubectl apply -k deploy/k8s/overlays/gcp
```

デプロイ前に Secret を設定する。

```bash
kubectl create secret generic cistanas-secrets \
  --from-literal=CistaNas__Jwt__SigningKey=<base64-32-byte-key> \
  --from-literal=CistaNas__Storage__BucketOrContainer=<bucket-name> \
  -n cistanas
```

各 overlay の構成:

| Overlay | PVC ストレージクラス | ストレージプロバイダ | Ingress |
|---|---|---|---|
| `aws` | `gp3` (20Gi) | S3 | ALB |
| `azure` | `managed-premium` (20Gi) | Azure Blob | Application Gateway |
| `gcp` | `pd-ssd` (20Gi) | GCS | GCE (静的 IP) |

## テスト

```bash
dotnet test
```

181 テスト（暗号化ラウンドトリップ、E2EE チャンク暗号/復号、ファイル操作、認証、WebDAV、ボリュームライフサイクル、パスサニタイズ、ストリーミングトークン等）。

## ライセンス

MIT

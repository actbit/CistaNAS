# CistaNAS

> 🌐 [English](./README.md) | 日本語

暗号化 NAS アプリケーション。.NET 10 + ASP.NET Core + Blazor Interactive Server rendering で構築。

ボリューム単位の暗号化（サーバー暗号化 AES-XTS / E2EE AES-256-GCM）、マルチユーザー鍵管理、ジャーナリング、メディアストリーミング、WebDAV、Dokan.NET クライアント対応。

## 機能

- **ボリューム暗号化** — AES-XTS (IEEE 1619) によるセクタ単位の透過暗号化。暗号化なしのボリュームも作成可能
- **チャンクベースストレージ** — volume.dat を S3/R2 等にチャンク分割保存。VPS のローカルディスクを不要に。サーバー暗号化・E2EE 両対応
- **E2EE（エンドツーエンド暗号化）** — クライアント側 AES-256-GCM チャンク暗号化。サーバーは暗号化済みデータのみを保持し、平文にアクセス不可
- **マルチユーザー鍵管理** — ユーザーごとに独立した Argon2id+PBKDF2 → KEK でマスターキーをラップ。パスワード変更時は対象ユーザーのエントリのみ再ラップ
- **共有ボリューム** — オーナーが他ユーザーにアクセス権を付与・取り消し可能。グループ単位のアクセス制御にも対応
- **メディアストリーミング** — ブラウザでの動画再生・写真プレビュー。通常ボリュームは HTTP Range 要求でシーク対応、E2EE ボリュームはチャンク単位の Blob URL プレビュー
- **クライアント対応** — ブラウザ (Blazor + Web Crypto API)、Windows (Dokan.NET 仮想ファイルシステム)、Android、WebDAV (rclone / RCX)
- **組み込みViewer** — Windowsはマウント済みボリュームの画像・テキストをRAMで表示。Androidは画像・テキスト・動画・音声・PDF（PDFはAndroid 8以降）に対応し、暗号化チャンクまたはHTTP Rangeを必要な範囲だけ読み込む。復号ファイルのキャッシュや外部アプリへの共有は行わない
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
| `CistaNAS.Mobile.Core` | Androidのロジック・ストリーミング読み取り（UI非依存） |
| `CistaNAS.Mobile` | 組み込みViewerを備えるAndroidクライアント |
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
      PasswordHasher         ASP.NET Identity パスワードハッシュ（旧 PBKDF2 互換）
      KeyDerivation          Argon2id + PBKDF2 合成 KEK 導出 (RFC 9106)
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

### MinIO（S3 互換ストレージ）付きで起動

環境変数 `ENABLE_MINIO=true` で Aspire が MinIO コンテナを起動し、webfrontend を S3 バックエンドに自動切替します。デフォルト（未設定）は local ストレージで本番影響なし。

Dockerが必要です。初回は `deploy/minio/Dockerfile` に固定した公式MinIOリリースのコミットから
開発・テスト用イメージをビルドするため、数分かかる場合があります。[コミュニティ版はソース配布](https://github.com/minio/minio)
に移行しており、`minio/minio:latest` は使用しません。コンテナテストの前にビルドする場合は
`docker build -t cistanas-minio:integration-test deploy/minio` を実行し、テストプロセスに
`MINIO_IMAGE=cistanas-minio:integration-test` を設定します（PowerShellでは
`$env:MINIO_IMAGE = 'cistanas-minio:integration-test'`）。CIでも先にビルドします。

```bash
# 環境変数で指定
ENABLE_MINIO=true dotnet run --project CistaNAS.AppHost

# またはコマンドライン引数で
dotnet run --project CistaNAS.AppHost -- --ENABLE_MINIO true
```

MinIOコンソールはAspireダッシュボードに表示されるエンドポイントから開きます（認証: `minioadmin` / `minioadmin`）。

通常のAppHost起動ではDockerボリューム `minio-data` を保持します。統合テストではこのマウントを外し、
使い捨てのコンテナ領域を利用して、開始時にバケットが空であることを確認します。すでに `minio-data` に
残っている過去のテストデータは保持します。更新によって既存ボリュームやオブジェクトは削除しません。

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
      "KdfAlgorithm": "argon2id",
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
| `Auth:Argon2MemoryKiB` | ログインハッシュの Argon2id メモリ量 KiB（デフォルト 65,536 = 64 MiB） |
| `Auth:Argon2TimeCost` | ログインハッシュの Argon2id パス数（デフォルト 4） |
| `Auth:Argon2Parallelism` | ログインハッシュの Argon2id 並列度（デフォルト 4） |
| `Auth:Pbkdf2Iterations` | （レガシー）旧パスワードハッシュの PBKDF2 反復回数。新規ハッシュは Argon2id |
| `Volume:SectorSize` | AES-XTS のセクタサイズ（16 の倍数） |
| `Volume:KdfAlgorithm` | KEK 導出アルゴリズム: `argon2id`（Argon2id+PBKDF2 合成、デフォルト）or `argon2id-raw`（Argon2id 単独、RFC 9106 標準構成） |
| `Volume:KdfMemoryKiB` | KEK 導出の Argon2id メモリ量 KiB（デフォルト 65,536 = 64 MiB） |
| `Volume:KdfTimeCost` | KEK 導出の Argon2id パス数（デフォルト 4） |
| `Volume:KdfParallelism` | KEK 導出の Argon2id 並列度（デフォルト 4） |
| `Volume:KdfIterations` | KEK 導出の後段 PBKDF2 反復回数（デフォルト 600,000。`Volume:KdfAlgorithm` = `argon2id-raw` 時は不使用） |
| `Volume:DefaultEncryptionMode` | デフォルト暗号化モード（`server` / `e2ee` / `none`） |
| `Volume:E2eeChunkSize` | E2EE チャンクサイズ（バイト、デフォルト 1 MiB） |
| `Volume:ChunkStorage` | チャンクストレージモード（`local` = 常に volume.dat / `auto` = S3 使用時に自動チャンク） |
| `Volume:ServerChunkSize` | チャンクモード時のサーバー側チャンクサイズ（バイト、デフォルト 4 MiB） |

## 暗号化の仕組み

### サーバー暗号化（AES-XTS）

```
ログインパスワード
  └ Argon2id(password, SHA256(username) || salt, t=4, m=64MiB, p=4)   [RFC 9106]
      └ PBKDF2-SHA256(argon2out, SHA256(username) || salt, 600,000) → KEK
          └ AES-256-GCM でマスターキーをアンラップ
          └ マスターキー (64B) で AES-XTS ボリュームデータを暗号/復号
```

`Volume:KdfAlgorithm = "argon2id-raw"` にすると新規ボリューム作成時の KDF が Argon2id 単独
（`KEK = Argon2id(...)` をそのまま使用、PBKDF2 後段なし）になります。KDF 種別はボリューム
ヘッダごとに永続化されるため、既存ボリュームはどちらの設定でも元の導出方式のまま動作します。

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
  └ Argon2id(password, SHA256(username) || salt, t=4, m=64MiB, p=4)   [RFC 9106]
      └ PBKDF2-SHA256(argon2out, SHA256(username) || salt, 600,000) → KEK (32B)
          └ AES-256-GCM でマスターキーを wrap/unwrap
          └ マスターキー (32B) はクライアント側でのみ生成・保持

ファイルごと:
  HKDF-SHA256(masterKey, fileSalt, "cista-file-key") → FileKey (32B)
    └ チャンクごと:
        Nonce = HMAC-SHA256(FileKey, fileSalt || chunkIndex)[0:12]
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

- **マスターキーはクライアントでのみ生成**され、サーバーには送信されない
- **Nonce 導出に fileSalt を含める** — FileKey 漏洩時の予測可能性を低減
- **認証タグ付き暗号化** — AES-256-GCM / ChaCha20-Poly1305 で完全性保証
- **サーバー侵害でも安全** — 暗号化済みデータとラップ済み鍵しか漏洩しない
- **パスワード紛失時は復旧不可能** — クライアント側でのみ鍵を保持

### E2EE共有解除の保証と制限

共有解除後はサーバーへのアクセスを拒否し、共有v2では残るメンバー向けに新しいGroupKeyを発行します。
**ファイル鍵の再ラップはDEKの交換ではありません。** 既存ファイルのDEKは同じなので、旧メンバーが
DEK（または旧GroupKeyと旧ラップ）を保存していた場合、別経路で入手した更新後の暗号文も復号できます。
epochやAADの変更だけでは、このアクセスを防げません。過去に取得した平文・暗号文も取り消せません。

更新後の内容を旧メンバーから暗号学的に分離するには、**新しいファイルID・ランダムなDEK・ソルト**で
全体を再暗号化し、保存完了と内容確認の後に元ファイルを削除する必要があります。ブラウザー・Androidの
組み込みアップロードは新しいファイルを作成しますが、Dokanで既存ファイルを編集してもDEKは交換されません。
旧v1形式では公開ソルトと同じマスターキーからファイル鍵を導出するため、マスターキーを保持する旧メンバーは
新規アップロードも復号できます。置換ファイルをアップロードする前に共有v2への移行が必要です。
既存ファイルのDEKを自動かつ原子的に交換する機能は未実装です。APIのrevokeだけではGroupKeyも交換されません。

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

- **認証タイミング攻撃対策** — ユーザー存在の有無に関わらず応答時間を均一化（ダミー Argon2id 計算）
- **パスサニタイザ** — ディレクトリトラバーサル防止（API・WebDAV 両対応）
- **レート制限** — 認証エンドポイント 10 req/min/IP、API 全体 100 req/min/IP
- **認証ロックアウト** — 5 回失敗で 15 分間ロック（1 試行ごとに Argon2id ハッシュ 64 MiB / 4 パスのコスト）
- **セキュリティヘッダ** — CSP, HSTS, X-Content-Type-Options, X-Frame-Options 等
- **JWT 署名鍵** — 本番環境で 32 バイト以上必須（開発環境ではランダム生成）
- **ストリーミングトークン** — 60 秒有効・短命・URL ベースアクセス用・最大 10,000 個
- **エラーメッセージ** — 資格情報の情報漏洩なし（セキュリティログのみ詳細を記録）
- **Kestrel** — リクエストボディ上限 10 GiB、ヘッダタイムアウト 30 秒
- **鍵消去** — メモリ内の鍵（マスターキー・KEK）を `CryptographicOperations.ZeroMemory` で消去

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

## DB復旧と更新時の容量・I/O

クラウドSQLiteは単一インスタンス専用です。ローカルDBとWALは永続ボリューム上の
`Storage:VolumeDataPath` に保存してください。SQLiteのbackup APIでWALのコミットを含む整合した
スナップショットを作り、`Database:SyncIntervalSeconds`（既定30秒）ごとに同期・失敗時の再試行を行います。
アップロードは直列化し、再起動時に既存ローカルDBを再送します。ダウンロードは原子的に反映し、
終了・キャンセル・Dispose後もローカル復旧元を保持します。

復旧DBは `<VolumeDataPath>/.cistanas-sqlite/<保存先とBlobKeyのSHA-256>/database.sqlite` に保存します。
未設定時も同じ分離方式を一時ディレクトリに適用します。実際のプロバイダ・エンドポイント・バケット／
コンテナ・プレフィックスを区別し、資格情報は識別子に含めません。Azureのキー／SASの更新だけでは復旧先は変わりません。
クラウドのオブジェクト名をローカルのパスとして扱いません。

旧形式の `<VolumeDataPath>/<BlobKey>` または一時ディレクトリ直下にDB・WAL・SHMが残っている場合、
保存先を特定できないため自動では取り込みません。旧BlobKeyが絶対パスや親ディレクトリを指す場合も、
ファイルを変更せず確認します。起動時のエラーに旧パスと新パスを表示し、元ファイルは保持します。
移行前にサーバーを停止してバックアップを取り、そのDBが現在の接続先に属することを確認してください。
DBと存在する `-wal`／`-shm` を、表示された新パスの `database.sqlite`／`database.sqlite-wal`／
`database.sqlite-shm` として移動します。稼働中のDB本体だけをコピーすると未チェックポイントの変更を失います。
移行後に起動して内容・同期を確認してください。接続先やBlobKeyを変える場合も、以前の復旧元は保持して確認してください。

一時ディレクトリへのフォールバックではコンテナ・ホストの交換に耐えられません。同期成功前にローカル
ボリュームを失えば最近の変更が失われる可能性があります。オブジェクトストレージは非同期の複製先です。
重要データには別バックアップを用意し、強い耐久性や複数インスタンスが必要ならPostgreSQLを使用してください。
同じクラウドSQLiteオブジェクトに複数のプロセスから書き込んではいけません。

ローカル部分更新は、全体を別領域へ保存してからカタログを切り替えます。空き領域の再利用と、更新・削除後の
不要な末尾の切り詰めにより、同じサイズの繰り返し更新による容量増加を抑えます。更新中は単一ファイルでも
約2倍の容量が必要になり、空き領域の断片化や他ファイルによってはさらに必要です。コピー・旧領域の消去には
ファイル全体に比例するI/Oが残ります。16 MiBファイルの反復更新テストで時間と物理容量を記録します。
汎用的なオンライン圧縮・差分に比例するI/Oへの変更は未実装です。

オブジェクトストレージではE2EEの未確定チャンクを再更新した際、新しいカタログの保存後に
古い未確定世代を削除します。公開済み更新の旧世代削除は、リクエストのキャンセルに依存せず再試行します。
削除失敗が続く場合やプロセスが停止した場合は孤児オブジェクトが残る可能性があります。
過去の孤児オブジェクトを自動収集するバックグラウンド処理は未実装です。

## テスト

GitHub ActionsでPR・masterへのpush時に、Windowsのサーバー／クライアントテスト、Chromiumのブラウザー
テスト、LinuxのMinIO／PostgreSQL統合テスト、Android Debug x64／Release arm64ビルドを実行します。
TRX結果を成果物として保存します。実DokanドライバテストはドライバのあるWindows環境で実行するため、
ホスト型CIから除外します。AndroidのネイティブViewerには端末・エミュレーターが必要です
（`CistaNAS.Mobile/Testing/README.md` を参照）。同一checkoutではWebビルドがWASM出力を共有するため、
テストプロジェクトのビルドを順番に行います。

```bash
dotnet test
```

181 テスト（暗号化ラウンドトリップ、E2EE チャンク暗号/復号、ファイル操作、認証、WebDAV、ボリュームライフサイクル、パスサニタイズ、ストリーミングトークン等）。

## ライセンス

MIT

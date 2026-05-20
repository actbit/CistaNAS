# CistaNAS

暗号化 NAS アプリケーション。.NET 10 + ASP.NET Core + Blazor Interactive Server rendering で構築。

ボリューム単位の暗号化（サーバー暗号化 AES-XTS / E2EE AES-256-GCM）、マルチユーザー鍵管理、ジャーナリング、メディアストリーミング、WebDAV、Dokan.NET クライアント対応。

## 機能

- **ボリューム暗号化** — AES-XTS (IEEE 1619) によるセクタ単位の透過暗号化。暗号化なしのボリュームも作成可能
- **E2EE（エンドツーエンド暗号化）** — クライアント側 AES-256-GCM チャンク暗号化。サーバーは暗号化済みデータのみを保持し、平文にアクセス不可
- **マルチユーザー鍵管理** — ユーザーごとに独立した PBKDF2 → KEK でマスターキーをラップ。パスワード変更時は対象ユーザーのエントリのみ再ラップ
- **共有ボリューム** — オーナーが他ユーザーにアクセス権を付与・取り消し可能。グループ単位のアクセス制御にも対応
- **メディアストリーミング** — ブラウザでの動画再生・写真プレビュー。通常ボリュームは HTTP Range 要求でシーク対応、E2EE ボリュームはチャンク単位の Blob URL プレビュー
- **3 クライアント対応** — ブラウザ (Blazor + Web Crypto API)、Windows (Dokan.NET 仮想ファイルシステム)、WebDAV (rclone / RCX)
- **ジャーナリング** — 書き込み操作のクラッシュリカバリ
- **WebDAV** — 外部クライアントから直接アクセス可能
- **REST API** — `/api/v1` にボリューム・ファイル・認証・E2EE・ストリーミングエンドポイントを提供
- **セットアップウィザード** — 初回起動時に管理者ユーザーを作成

## ソリューション構成

| プロジェクト | 役割 |
|---|---|
| `CistaNAS.AppHost` | .NET Aspire オーケストレーション |
| `CistaNAS.Web` | Blazor WebUI + REST API + WebDAV（単一プロセス） |
| `CistaNAS.Client` | Dokan.NET Windows 仮想ファイルシステムクライアント |
| `CistaNAS.ServiceDefaults` | Aspire 共通設定（テレメトリ・ヘルスチェック） |
| `CistaNAS.Tests` | xUnit テスト (181 tests) |

## アーキテクチャ

```
Pages (Blazor) / API Endpoints / WebDAV Handler
  └ リクエスト受付・レスポンス返却
Services
  └ ビジネスロジック
      VolumeService          ボリューム作成・マウント・ロック・アクセス管理 (Singleton)
      FileService            ファイル CRUD・一覧 (Scoped)
      E2eeFileService        E2EE ボリュームのカタログ・チャンク管理 (Scoped)
      StreamingTokenService  メディアストリーミング用短命トークン (Singleton)
      JournalService         ジャーナル記録・復旧 (Scoped)
      AuthService            認証・JWT 発行 (Scoped)
      UserStore              ユーザー管理・パスワード検証 (Scoped)
      GroupStore             グループ管理 (Singleton)
      InvitationService      招待コード管理 (Scoped)
Crypto / Volume / Journal
  └ 低レベル実装
      AesXtsStream           AES-XTS seekable ストリーム
      E2eeCrypto             AES-256-GCM チャンク暗号化 (Client)
      PasswordHasher         PBKDF2-SHA256 パスワードハッシュ
      KeyDerivation          KEK 導出 (PBKDF2)
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
      "KdfIterations": 310000
    }
  }
}
```

| 項目 | 説明 |
|---|---|
| `DataRoot` | ボリュームデータ・ジャーナル・ユーザー情報の保存先 |
| `Jwt:SigningKey` | 未設定時は起動ごとにランダム生成（再起動でトークン失効） |
| `Jwt:AccessTokenMinutes` | アクセストークンの有効期限（分） |
| `Auth:Pbkdf2Iterations` | パスワードハッシュの反復回数 |
| `Volume:SectorSize` | AES-XTS のセクタサイズ（16 の倍数） |
| `Volume:KdfIterations` | KEK 導出の PBKDF2 反復回数 |

## 暗号化の仕組み

### サーバー暗号化（AES-XTS）

```
ログインパスワード
  └ PBKDF2(password, SHA256(username) || salt, iterations) → KEK
      └ AES-256-GCM でマスターキーをアンラップ
          └ マスターキー (64B) で AES-XTS ボリュームデータを暗号/復号
```

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

## テスト

```bash
dotnet test
```

181 テスト（暗号化ラウンドトリップ、E2EE チャンク暗号/復号、ファイル操作、認証、WebDAV、ボリュームライフサイクル、パスサニタイズ、ストリーミングトークン等）。

## ライセンス

MIT

# CistaNAS

暗号化 NAS アプリケーション。.NET 10 + ASP.NET Core + Blazor Interactive Server rendering で構築。

ボリューム単位の暗号化（サーバー暗号化 AES-XTS / E2EE AES-256-GCM）、マルチユーザー鍵管理、ジャーナリング、WebDAV、Dokan.NET クライアント対応。

## 機能

- **ボリューム暗号化** — AES-XTS (IEEE 1619) によるセクタ単位の透過暗号化。暗号化なしのボリュームも作成可能
- **E2EE（エンドツーエンド暗号化）** — クライアント側 AES-256-GCM チャンク暗号化。サーバーは暗号化済みデータのみを保持し、平文にアクセス不可
- **マルチユーザー鍵管理** — ユーザーごとに独立した PBKDF2 → KEK でマスターキーをラップ。パスワード変更時は対象ユーザーのエントリのみ再ラップ
- **共有ボリューム** — オーナーが他ユーザーにアクセス権を付与・取り消し可能
- **3 クライアント対応** — ブラウザ (Blazor + Web Crypto API)、Windows (Dokan.NET 仮想ファイルシステム)、WebDAV (rclone / RCX)
- **ジャーナリング** — 書き込み操作のクラッシュリカバリ
- **WebDAV** — 外部クライアントから直接アクセス可能
- **REST API** — `/api/v1` にボリューム・ファイル・認証・E2EE エンドポイントを提供
- **セットアップウィザード** — 初回起動時に管理者ユーザーを作成

## ソリューション構成

| プロジェクト | 役割 |
|---|---|
| `CistaNAS.AppHost` | .NET Aspire オーケストレーション |
| `CistaNAS.Web` | Blazor WebUI + REST API + WebDAV（単一プロセス） |
| `CistaNAS.Client` | Dokan.NET Windows 仮想ファイルシステムクライアント |
| `CistaNAS.ServiceDefaults` | Aspire 共通設定（テレメトリ・ヘルスチェック） |
| `CistaNAS.Tests` | xUnit テスト (73 tests) |

## アーキテクチャ

```
Pages (Blazor) / API Endpoints / WebDAV Handler
  └ リクエスト受付・レスポンス返却
Services
  └ ビジネスロジック
      VolumeService    ボリューム作成・マウント・ロック・アクセス管理 (Singleton)
      FileService      ファイル CRUD・一覧 (Scoped)
      E2eeFileService  E2EE ボリュームのカタログ・チャンク管理 (Scoped)
      JournalService   ジャーナル記録・復旧 (Scoped)
      AuthService      認証・JWT 発行 (Scoped)
      UserStore        ユーザー管理・パスワード検証 (Scoped)
Crypto / Volume / Journal
  └ 低レベル実装
      AesXtsStream     AES-XTS seekable ストリーム
      E2eeCrypto       AES-256-GCM チャンク暗号化 (Client)
      PasswordHasher   PBKDF2-SHA256 パスワードハッシュ
      KeyDerivation    KEK 導出 (PBKDF2)
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

## E2EE API エンドポイント

```
POST /api/v1/e2ee/create-volume            E2EE ボリューム作成
POST /api/v1/e2ee/{volume}/mount            マウント（アクセス権チェック）
POST /api/v1/e2ee/{volume}/create-file      ファイルエントリ作成
POST /api/v1/e2ee/{volume}/upload-chunk/{fileId}/{index}  チャンクアップロード
GET  /api/v1/e2ee/{volume}/download-chunk/{fileId}/{index} チャンクダウンロード
PATCH /api/v1/e2ee/{volume}/finalize-file/{fileId}         アップロード確定
DELETE /api/v1/e2ee/{volume}/files/{fileId}                ファイル削除
GET  /api/v1/e2ee/{volume}/files            ファイル一覧
POST /api/v1/e2ee/{volume}/add-wrapped-key  共有鍵追加
```

## WebDAV アクセス

WebDAV クライアントから `https://<host>/dav/<volume-name>/` にアクセスする。

Basic 認証と JWT の両方に対応。

E2EE ボリュームの WebDAV は暗号化済みファイル名と暗号化済み blob をそのまま転送する。外部暗号化ツール（rclone crypt 等）との併用も可能。

## テスト

```bash
dotnet test
```

73 テスト（暗号化ラウンドトリップ、E2EE チャンク暗号/復号、ファイル操作、認証、WebDAV 等）。

## ライセンス

MIT

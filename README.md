# CistaNAS

暗号化 NAS アプリケーション。.NET 10 + ASP.NET Core + Blazor Interactive Server rendering で構築。

ボリューム単位の AES-XTS 暗号化、マルチユーザー鍵管理、ジャーナリング、WebDAV 対応を備える。

## 機能

- **ボリューム暗号化** — AES-XTS (IEEE 1619) によるセクタ単位の透過暗号化。暗号化なしのボリュームも作成可能
- **マルチユーザー鍵管理** — ユーザーごとに独立した PBKDF2 → KEK でマスターキーをラップ。パスワード変更時は対象ユーザーのエントリのみ再ラップ
- **共有ボリューム** — オーナーが他ユーザーにアクセス権を付与・取り消し可能。各ユーザーは自分のパスワードでマスターキーを復元
- **ジャーナリング** — 書き込み操作のクラッシュリカバリ
- **WebDAV** — rclone / RCX 等の外部クライアントから直接アクセス可能 (PROPFIND, GET, PUT, DELETE, MKCOL)
- **REST API** — `/api/v1` にボリューム・ファイル・認証エンドポイントを提供
- **セットアップウィザード** — 初回起動時に管理者ユーザーを作成

## ソリューション構成

| プロジェクト | 役割 |
|---|---|
| `CistaNAS.AppHost` | .NET Aspire オーケストレーション |
| `CistaNAS.Web` | Blazor WebUI + REST API + WebDAV（単一プロセス） |
| `CistaNAS.ServiceDefaults` | Aspire 共通設定（テレメトリ・ヘルスチェック） |
| `CistaNAS.Tests` | xUnit テスト (45 tests) |

## アーキテクチャ

```
Pages (Blazor) / API Endpoints / WebDAV Handler
  └ リクエスト受付・レスポンス返却
Services
  └ ビジネスロジック
      VolumeService   ボリューム作成・マウント・ロック・アクセス管理 (Singleton)
      FileService     ファイル CRUD・一覧 (Scoped)
      JournalService  ジャーナル記録・復旧 (Scoped)
      AuthService     認証・JWT 発行 (Scoped)
      UserStore       ユーザー管理・パスワード検証 (Scoped)
Crypto / Volume / Journal
  └ 低レベル実装
      AesXtsStream    AES-XTS seekable ストリーム
      PasswordHasher  PBKDF2-SHA256 パスワードハッシュ
      KeyDerivation   KEK 導出 (PBKDF2)
```

## 前提

- .NET 10 SDK

## 実行

```bash
dotnet run --project CistaNAS.AppHost
```

初回起動時は `/setup` にリダイレクトされ、管理者ユーザーの作成を求められる。

### 個別起動（Aspire なし）

```bash
dotnet run --project CistaNAS.Web
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

```
ログインパスワード
  └ PBKDF2(password, SHA256(username) || salt, iterations) → KEK
      └ AES-256-GCM でマスターキーをアンラップ
          └ マスターキーで AES-XTS ボリュームデータを暗号/復号
```

- 各ユーザーに固有のソルトで KEK を導出
- マスターキーはユーザーごとにラップされ、`VolumeHeader` に保存
- パスワード変更時は対象ユーザーのラップ済み鍵のみ再ラップ（他ユーザーへの影響なし）

## WebDAV アクセス

WebDAV クライアントから `https://<host>/dav/<volume-name>/` にアクセスする。

Basic 認証と JWT の両方に対応。

## テスト

```bash
dotnet test
```

## ライセンス

MIT

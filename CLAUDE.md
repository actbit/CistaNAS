# CistaNAS — プロジェクト規約

暗号化NAS（ボリューム暗号化・ジャーナリング・認証付き）。.NET Aspire ソリューション。

## ソリューション構成（現状）

| プロジェクト | 役割 |
|---|---|
| `CistaNAS.AppHost` | Aspire オーケストレーション（`apiservice` と `webfrontend` を起動・参照） |
| `CistaNAS.ApiService` | Minimal API。外部クライアント（rclone・RCX 等）向け REST |
| `CistaNAS.Web` | Blazor（Interactive Server rendering）。WebUI |
| `CistaNAS.ServiceDefaults` | Aspire 共通設定（テレメトリ・ヘルスチェック・サービスディスカバリ） |
| `CistaNAS.Tests` | テスト |

## アーキテクチャ指針

### レイヤー構成（責務分離を厳守）

```
Controllers / Pages（Blazor）
  └ リクエスト受付・レスポンス返却のみ。ビジネスロジックを書かない
Services
  └ ビジネスロジックをすべてここに集約
      VolumeService   ボリュームの作成・マウント・ロック
      FileService     ファイルの読み書き・一覧・削除
      JournalService  ジャーナリングの記録・復旧
      AuthService     パスワード検証・JWT発行
Crypto / Volume / Journal
  └ 低レベル実装（AesXtsStream 等）。Services から呼ばれる
```

- Controllers / Blazor Pages にビジネスロジックを書かない。必ず Service に委譲する。
- Service から下位レイヤー（Crypto / Volume / Journal）を呼ぶ。逆方向の依存を作らない。

### DI 登録

- 全 Service を `AddScoped` または `AddSingleton` で登録する。
- **`VolumeService` はマウント状態を保持するため `AddSingleton`。**
- 状態を持たない Service は `AddScoped` を基本とする。

### Blazor 対応

- Blazor テンプレートのデフォルト構成を維持する。
- WebUI は Blazor コンポーネントで実装する。
- REST API エンドポイント（`/api/v1`）は外部クライアント（rclone・RCX 等）向けに引き続き提供する。
- Blazor コンポーネントからは Service を直接インジェクトしてよい（API 経由にしなくてよい）。
- Interactive Server rendering を使用する。

## 現状構成との整合メモ（実装前に要決定）

Aspire テンプレートは `ApiService` と `Web` が**別プロセス**。一方、指針では
`VolumeService` を `AddSingleton`（マウント状態を 1 つ保持）とし、かつ Blazor から
Service を直接インジェクトする。別プロセスのままだと API 側と Blazor 側で
シングルトンが分離し、マウント状態が共有されない。

→ Service 層（および `/api/v1`）を `CistaNAS.Web` 側に集約して単一プロセスにするか、
状態を外部ストア化するか、実装着手時に方針を確定すること。本ファイルは指針の
記録のみ。コードはまだ変更していない。

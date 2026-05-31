# CistaNAS — プロジェクト規約

暗号化NAS（ボリューム暗号化・ジャーナリング・認証付き）。.NET Aspire ソリューション。

## ソリューション構成（現状）

| プロジェクト | 役割 |
|---|---|
| `CistaNAS.AppHost` | Aspire オーケストレーション（`webfrontend` を起動） |
| `CistaNAS.Web` | Blazor（Interactive Server rendering）+ REST API（`/api/v1`）。**単一プロセス構成** |
| `CistaNAS.ServiceDefaults` | Aspire 共通設定（テレメトリ・ヘルスチェック・サービスディスカバリ） |
| `CistaNAS.Client` | クライアントサイド（Blazor コンポーネント用） |
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

## 単一プロセス構成について

現在、`CistaNAS.Web` プロジェクトに Blazor と REST API（`/api/v1`）の両方を集約した
**単一プロセス構成**をとっています。

### 理由

- `VolumeService` はマウント状態をインメモリで保持する `AddSingleton` サービス
- 別プロセス構成（`ApiService` と `Web` が分離）だと、Singleton インスタンスが各プロセスで
  独立してしまい、マウント状態が共有されない
- 単一プロセス構成により、Blazor WebUI と REST API クライアント（rclone・RCX 等）が
  同じ `VolumeService` インスタンスを共有し、マウント状態が正しく同期される

### 実装箇所

- `ServiceCollectionExtensions.cs` L40: `services.AddSingleton<VolumeService>();`
- `Program.cs` L278-280: `/api/v1` REST API エンドポイントの定義
- `AppHost.cs`: `webfrontend` のみを登録（単一プロセス構成）

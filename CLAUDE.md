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

## 共有プロジェクト CistaNAS.Shared

暗号化プリミティブ（AES-XTS, ChaCha20-Poly1305, E2EE, HKDF）は `CistaNAS.Shared` プロジェクト
（net10.0 クラスライブラリ）に集約。Web (Blazor/Server) と Client (Avalonia/Dokan) 双方から
参照され、重複実装を排除。

- `CistaNAS.Shared/Crypto/`: CipherAlgorithm, KeyDerivation, AesXtsStream, AesXtsTransform,
  ChunkEncryptor, ChaCha20Poly1305, E2eeCrypto
- `CistaNAS.Web/Crypto/`: PasswordHasher のみ（Identity 専用、サーバー側のみ）

## CistaNAS.Client の役割

`CistaNAS.Client` は Avalonia 12 + DokanNet を使った **Windows 用 Dokan マウントクライアント**。
サーバー上のボリュームを Windows のドライブ文字にマウントし、ローカルファイルシステムとして
利用可能にする。E2EE モード / 非 E2EE モード両対応。

- ターゲット: `net10.0-windows`, `WinExe`
- DokanNet: CistaNasFileSystem (IDokanOperations 実装) でボリュームをマウント
- Crypto: 共有プロジェクトの `E2eeCrypto` を使用

## 重要なセキュリティ・整合性の修正履歴

- **2026-06-02 Phase 1**: ChaCha20 ノンス ECB 化修正 (HKDF)、パストラバーサル修正、E2EE 鍵残留修正、AesXtsStream async I/O、起動時 Journal 復旧、E2EE 暗号化長計算共有化
- **2026-06-02 Phase 2**: CistaNAS.Shared への Crypto コード集約、重複削除
- **2026-06-02 Phase 3-4**: AsyncFileGate キャンセルバグ修正、E2EE チャンク範囲チェック、AddWrappedKey 認可、SetUserQuota 競合、Rewrap ロールバック、CistaAuthorizationHandler タイミング均一化、PBKDF2 DoS 対策

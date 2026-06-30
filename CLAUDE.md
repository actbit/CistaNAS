# CistaNAS — プロジェクト規約

暗号化NAS（ボリューム暗号化・ジャーナリング・認証付き）。.NET Aspire ソリューション。

## ソリューション構成（現状）

| プロジェクト | 役割 |
|---|---|
| `CistaNAS.AppHost` | Aspire オーケストレーション（`webfrontend` を起動） |
| `CistaNAS.Web` | **WASM SPA 配信 + REST API（`/api/v1`）+ WebDAV** のホスト。**単一プロセス構成** |
| `CistaNAS.Wasm` | Blazor WebAssembly フロントエンド（ブラウザ側 E2EE 暗号化）。`Web` が配信 |
| `CistaNAS.ServiceDefaults` | Aspire 共通設定（テレメトリ・ヘルスチェック・サービスディスカバリ） |
| `CistaNAS.Client` | Windows 用 Dokan マウントクライアント（Avalonia + DokanNet） |
| `CistaNAS.Shared` | 暗号化プリミティブ（Web / Client / Wasm で共有） |
| `CistaNAS.Tests` | xUnit 単体・統合テスト |
| `CistaNAS.PlaywrightTests` | Playwright によるブラウザ E2E テスト（CSP 検出・UI 回帰・実 JS 暗号化検証） |

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

### フロントエンド（WASM SPA）

- WebUI は `CistaNAS.Wasm`（Blazor WebAssembly）で実装。`CistaNAS.Web` が配信（`MapFallbackToFile("index.html")` で SPA フォールバック）。Server-side Blazor（Interactive Server）は使わない。
- WASM は Service を直接インジェクトせず、**REST API（`/api/v1`）経由**でサーバーと通信する（ブラウザ側の HttpClient + `AuthHeaderHandler` で JWT 自動付与）。
- REST API は WASM フロントエンドと外部クライアント（rclone・RCX・Dokan 等）の両方から利用。
- E2EE の暗号化は WASM 側の JS（`wwwroot/js/e2ee.js`, Web Crypto API）で行う。C# 側（`E2eeInterop`）は JS interop ラッパー。
- CSP は `script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'`（`unsafe-inline` は .NET 10 の `<script type="importmap">` に必須、`wasm-unsafe-eval` で Mono ランタイムを許可しつつ任意 JS `eval` を遮断）。

## 単一プロセス構成について

`CistaNAS.Web` プロジェクトに REST API（`/api/v1`）・WebDAV・WASM 配信を集約した
**単一プロセス構成**をとっています。

### 理由

- `VolumeService` はマウント状態をインメモリで保持する `AddSingleton` サービス
- 別プロセス構成だと Singleton インスタンスが各プロセスで独立し、マウント状態が共有されない
- 単一プロセス構成により、REST API（WASM フロントエンド・rclone・RCX）・WebDAV・Dokan クライアントが
  同じ `VolumeService` インスタンスを共有し、マウント状態が正しく同期される
  （WASM フロントエンドは API 経由なので状態を直接持たない）

### 実装箇所

- `ServiceCollectionExtensions.cs`: `services.AddSingleton<VolumeService>();`
- `Web/Program.cs`: `/api/v1` REST API エンドポイント、`/dav` WebDAV、`MapFallbackToFile("index.html")` で WASM 配信
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
- **2026-06-29**: WASM フロントエンド セキュリティ修正（CSP 厳格化 `wasm-unsafe-eval`、JWT 期限 60→30 分、インライン style/onclick 除去）。E2EE エッジケース E2E テスト（Aspire）追加
- **2026-06-30**: Playwright ブラウザ E2E テスト導入（CSP 違反検出・UI 回帰・実 JS 暗号化ラウンドトリップ）。過程で4つの潜在バグを発見修正: HttpClient `InnerHandler` 未設定（`net_http_handler_not_assigned`）、JWT クレームパース（`JsonWebTokenHandler` の長いURI非対応 → Sub/長いURI対応）、`e2ee.js` の fileKey `extractable=false`、CSP ImportMap ブロック（`unsafe-inline` 復活）
- **2026-07-01**: JWT 401 自動検知（`AuthHeaderHandler` → ログアウト + ログイン遷移）、レスポンス圧縮有効化、Bootstrap/Bootstrap Icons 配備、`eval`（DownloadFile）→ `cista.openUrl`、Server-side Blazor デッドコード整理

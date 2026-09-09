namespace CistaNAS.Shared.Crypto;

/// <summary>pin 検証の結果。</summary>
public enum PinCheckStatus
{
    /// <summary>pin 未登録。TOFU として初回 pin を作成して続行してよい。</summary>
    FirstUse,

    /// <summary>fingerprint 一致。続行可。</summary>
    Match,

    /// <summary>
    /// fingerprint 不一致。サーバー侵害または鍵更新の可能性。
    /// 自動的に新しい鍵を信頼してはならず、ユーザーの明示的操作でのみ pin を更新する。
    /// </summary>
    Mismatch,
}

/// <summary>pin 検証ロジック（全クライアント共通）。</summary>
public static class PublicKeyPinning
{
    /// <summary>
    /// 取得した公開鍵を保存済み pin と照合する。
    /// <see cref="PinCheckStatus.Mismatch"/> の場合は共有処理を中断すること。
    /// </summary>
    public static PinCheckStatus Check(TrustedPublicKeyPin? pin, byte[] publicKeyRaw)
    {
        if (publicKeyRaw is null || publicKeyRaw.Length == 0)
            throw new ArgumentException("公開鍵が空です。", nameof(publicKeyRaw));

        string fingerprint = E2eeV2.ComputeFingerprint(publicKeyRaw);
        if (pin is null || string.IsNullOrEmpty(pin.FingerprintSha256))
            return PinCheckStatus.FirstUse;

        return string.Equals(pin.FingerprintSha256, fingerprint, StringComparison.OrdinalIgnoreCase)
            ? PinCheckStatus.Match
            : PinCheckStatus.Mismatch;
    }

    /// <summary>新規 pin を作成する（TOFU 初回登録、またはユーザーの明示的な「新しい鍵を信頼する」操作）。</summary>
    public static TrustedPublicKeyPin CreatePin(string username, byte[] publicKeyRaw)
    {
        var now = DateTimeOffset.UtcNow;
        return new TrustedPublicKeyPin
        {
            Username = username,
            FingerprintSha256 = E2eeV2.ComputeFingerprint(publicKeyRaw),
            CreatedAt = now,
            UpdatedAt = now,
        };
    }
}

/// <summary>
/// クライアント側に保存する公開鍵 pin（TOFU trust anchor）。
/// ユーザー名ごとに初回取得した公開鍵の fingerprint を記録し、
/// 以降の取得時に fingerprint が変わっていれば共有を中断する。
/// このレコードはサーバーには送信しない（クライアントローカルのみ）。
/// </summary>
public sealed class TrustedPublicKeyPin
{
    /// <summary>pin 対象のユーザー名。</summary>
    public string Username { get; set; } = "";

    /// <summary>信頼済み公開鍵の fingerprint（SHA-256(rawPublicKey)、大文字 hex）。</summary>
    public string FingerprintSha256 { get; set; } = "";

    /// <summary>将来拡張: 鍵識別子（Identity key 署名モデル導入時に使用）。</summary>
    public string? KeyId { get; set; }

    /// <summary>将来拡張: pin 元の鍵（base64 raw）。サーバー再構築後の再検証に使用可。秘密情報ではない。</summary>
    public string? PublicKeyBase64 { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// 公開鍵メタデータの将来拡張モデル（データ定義のみ、現行プロトコルでは未使用）。
/// Account Identity Signing Key → Device ECDH Keys の署名モデルに移行できるよう、
/// 公開鍵を username 単一値に固定しないための envelope。
/// </summary>
public sealed class UserPublicKeyEnvelope
{
    /// <summary>鍵の所有者（アカウント ID）。将来は username から独立した ID に移行可。</summary>
    public string UserId { get; set; } = "";

    /// <summary>Device 単位の鍵の場合のデバイス識別子。</summary>
    public string? DeviceId { get; set; }

    /// <summary>鍵識別子（Identity 署名モデルでの参照用）。</summary>
    public string? KeyId { get; set; }

    /// <summary>raw 公開鍵（P-256 非圧縮点 65 バイト）。</summary>
    public byte[] PublicKey { get; set; } = [];

    /// <summary>SHA-256(PublicKey) の fingerprint（大文字 hex）。</summary>
    public string? FingerprintSha256 { get; set; }

    /// <summary>将来拡張: Account Identity Signing Key による署名（新しい Device Key の検証用）。</summary>
    public byte[]? Signature { get; set; }

    public DateTimeOffset? CreatedAt { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }
}

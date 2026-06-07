namespace CistaNAS.Shared.Crypto;

/// <summary>
/// プラットフォームに応じた AES-ECB 実装を生成するファクトリ。
/// ブラウザ WASM では Managed 実装、その他では System.Security.Cryptography を使用。
/// </summary>
internal static class AesEcbFactory
{
    /// <summary>暗号化専用の AES-ECB を作成。</summary>
    public static IAesEcb CreateEncryptor(ReadOnlySpan<byte> key)
    {
        if (OperatingSystem.IsBrowser())
            return new ManagedAesEcb(key);
        else
            return new SystemAesEcb(key, encrypt: true);
    }

    /// <summary>暗号化 + 復号 両対応の AES-ECB を作成。</summary>
    public static IAesEcb CreateFull(ReadOnlySpan<byte> key)
    {
        if (OperatingSystem.IsBrowser())
            return new ManagedAesEcb(key);
        else
            return new SystemAesEcb(key, encrypt: null); // both directions
    }
}

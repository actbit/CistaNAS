using System.Text.Json;
using Microsoft.JSInterop;

namespace CistaNAS.Wasm.Services;

/// <summary>
/// パスワードベース KDF のパラメータ（JS の normalizeKdf にそのまま渡す）。
/// Algorithm == "argon2id" は合成 KDF を意味する:
/// KEK = PBKDF2-SHA256( Argon2id(password, salt, TimeCost, MemoryKiB, Parallelism), salt, Iterations, 32 )
/// （Shared の KdfSpec・サーバー VolumeHeader.KdfParams と同じ wire format）
/// </summary>
public sealed record E2eeKdfOptions(string Algorithm, int Iterations, int MemoryKiB, int TimeCost, int Parallelism)
{
    public const string Argon2id = "argon2id";
    public const string Pbkdf2Sha256 = "pbkdf2-sha256";

    /// <summary>サーバー設定に基づく新規作成用スペック（Argon2id + PBKDF2 合成）。</summary>
    public static E2eeKdfOptions NewArgon2id(int iterations, int memoryKiB, int timeCost, int parallelism) =>
        new(Argon2id, iterations, memoryKiB, timeCost, parallelism);

    /// <summary>レガシー PBKDF2 単段（既存データの検証用）。</summary>
    public static E2eeKdfOptions LegacyPbkdf2(int iterations) => new(Pbkdf2Sha256, iterations, 0, 0, 0);
}

/// <summary>
/// Blazor から JavaScript の E2EE モジュールを呼び出すインタープロ。
/// JS 側で CryptoKey を Map にキャッシュし、文字列ハンドルで参照する。
/// </summary>
public sealed class E2eeInterop(IJSRuntime js) : IAsyncDisposable
{
    private IJSObjectReference? _module;

    private async ValueTask<IJSObjectReference> GetModule()
    {
        _module ??= await js.InvokeAsync<IJSObjectReference>("import", "./js/e2ee.js");
        return _module;
    }

    // ---- 鍵管理 ----

    /// <summary>レガシー PBKDF2 で KEK を導出する（既存呼び出し互換）。</summary>
    public Task<string> DeriveKek(string password, string saltBase64, int iterations, string? username = null)
        => DeriveKek(password, saltBase64, E2eeKdfOptions.LegacyPbkdf2(iterations), username);

    /// <summary>KDF スペックに応じて KEK を導出し、JS 側にキャッシュしてハンドルを返す。</summary>
    /// <param name="username">クロスプラットフォーム互換のため SHA256(username) をソルトに混入（KeyDerivation.DeriveKek と統一）。</param>
    public async Task<string> DeriveKek(string password, string saltBase64, E2eeKdfOptions kdf, string? username = null)
    {
        var mod = await GetModule();
        return await mod.InvokeAsync<string>("deriveKek", password, saltBase64, kdf, username as object);
    }

    /// <summary>
    /// localStorage の ECDH 秘密鍵 JSON（wrapped/nonce/salt/iterations + 任意の kdf フィールド）から
    /// KDF スペックを読み取る。旧スキーマ（iterations のみ）はレガシー PBKDF2 として扱う。
    /// </summary>
    public static E2eeKdfOptions ReadPrivKeyKdf(System.Text.Json.JsonElement root)
    {
        int iterations = root.TryGetProperty("iterations", out var it) && it.ValueKind == System.Text.Json.JsonValueKind.Number && it.TryGetInt32(out var i)
            ? i : 0;
        if (root.TryGetProperty("algorithm", out var alg) && alg.ValueKind == System.Text.Json.JsonValueKind.String
            && string.Equals(alg.GetString(), E2eeKdfOptions.Argon2id, StringComparison.Ordinal))
        {
            return new E2eeKdfOptions(
                E2eeKdfOptions.Argon2id,
                iterations,
                root.TryGetProperty("memoryKiB", out var m) && m.TryGetInt32(out var mv) ? mv : 0,
                root.TryGetProperty("timeCost", out var t) && t.TryGetInt32(out var tv) ? tv : 0,
                root.TryGetProperty("parallelism", out var p) && p.TryGetInt32(out var pv) ? pv : 0);
        }
        return E2eeKdfOptions.LegacyPbkdf2(iterations);
    }

    /// <summary>マスターキーを JS 側で生成してハンドルを返す。</summary>
    public async Task<string> GenerateMasterKey()
    {
        var mod = await GetModule();
        return await mod.InvokeAsync<string>("generateMasterKey");
    }

    /// <summary>マスターキーを KEK でラップして { nonce, ciphertext, tag } を返す。</summary>
    public async Task<(string Nonce, string Ciphertext, string Tag)> WrapMasterKey(string masterKeyHandle, string kekHandle)
    {
        var mod = await GetModule();
        var result = await mod.InvokeAsync<JsonElement>("wrapMasterKey", masterKeyHandle, kekHandle);
        return (result.GetProperty("nonce").GetString()!,
                result.GetProperty("ciphertext").GetString()!,
                result.GetProperty("tag").GetString()!);
    }

    /// <summary>ラップ済みマスターキーをアンラップしてハンドルを返す。</summary>
    public async Task<string> UnwrapMasterKey(string nonce, string ciphertext, string tag, string kekHandle)
    {
        var mod = await GetModule();
        return await mod.InvokeAsync<string>("unwrapMasterKey", nonce, ciphertext, tag, kekHandle);
    }

    /// <summary>鍵を JS 側から削除。</summary>
    public async Task ClearKey(string handle)
    {
        var mod = await GetModule();
        await mod.InvokeVoidAsync("clearKey", handle);
    }

    /// <summary>全鍵を JS 側から削除。</summary>
    public async Task ClearAllKeys()
    {
        var mod = await GetModule();
        await mod.InvokeVoidAsync("clearAllKeys");
    }

    // ---- ファイル名暗号化 ----

    public async Task<string> EncryptFilename(string plainName, string masterKeyHandle)
    {
        var mod = await GetModule();
        return await mod.InvokeAsync<string>("encryptFilename", plainName, masterKeyHandle);
    }

    public async Task<string> DecryptFilename(string encBase64, string masterKeyHandle)
    {
        var mod = await GetModule();
        return await mod.InvokeAsync<string>("decryptFilename", encBase64, masterKeyHandle);
    }

    // ---- チャンク操作 ----

    public async Task<string> EncryptChunk(byte[] plainBytes, string masterKeyHandle, int chunkIndex, string fileSaltBase64, bool isFirstChunk, int revision = 0)
    {
        var mod = await GetModule();
        string plainBase64 = Convert.ToBase64String(plainBytes);
        return await mod.InvokeAsync<string>("encryptChunk", plainBase64, masterKeyHandle, chunkIndex, fileSaltBase64, isFirstChunk, revision);
    }

    public async Task<byte[]> DecryptChunk(string encBase64, string masterKeyHandle, int chunkIndex, string fileSaltBase64, int revision = 0)
    {
        var mod = await GetModule();
        string plainBase64 = await mod.InvokeAsync<string>("decryptChunk", encBase64, masterKeyHandle, chunkIndex, fileSaltBase64, revision);
        return Convert.FromBase64String(plainBase64);
    }

    // ---- ヘルパー ----

    public async Task<string> GenerateFileSalt()
    {
        var mod = await GetModule();
        return await mod.InvokeAsync<string>("generateFileSalt");
    }

    public async ValueTask DisposeAsync()
    {
        if (_module is not null)
        {
            await _module.DisposeAsync();
            _module = null;
        }
    }

    // ---- ECDH key pair management ----

    public async Task<(string PublicKeyHandle, string PrivateKeyHandle)> GenerateKeyPair()
    {
        var mod = await GetModule();
        var result = await mod.InvokeAsync<JsonElement>("generateKeyPair");
        return (result.GetProperty("publicKeyHandle").GetString()!,
                result.GetProperty("privateKeyHandle").GetString()!);
    }

    public async Task<string> ExportPublicKey(string publicKeyHandle)
    {
        var mod = await GetModule();
        return await mod.InvokeAsync<string>("exportPublicKey", publicKeyHandle);
    }

    /// <summary>レガシー PBKDF2 で ECDH 秘密鍵をラップする（既存呼び出し互換）。</summary>
    public Task<(string Nonce, string Wrapped)> EncryptPrivateKey(
        string privateKeyHandle, string password, string saltBase64, int iterations)
        => EncryptPrivateKey(privateKeyHandle, password, saltBase64, E2eeKdfOptions.LegacyPbkdf2(iterations));

    public async Task<(string Nonce, string Wrapped)> EncryptPrivateKey(
        string privateKeyHandle, string password, string saltBase64, E2eeKdfOptions kdf)
    {
        var mod = await GetModule();
        var result = await mod.InvokeAsync<JsonElement>(
            "encryptPrivateKey", privateKeyHandle, password, saltBase64, kdf);
        return (result.GetProperty("nonce").GetString()!,
                result.GetProperty("wrapped").GetString()!);
    }

    /// <summary>レガシー PBKDF2 で ECDH 秘密鍵をアンラップする（既存呼び出し互換）。</summary>
    public Task<string> DecryptPrivateKey(
        string wrappedBase64, string nonceBase64, string password, string saltBase64, int iterations)
        => DecryptPrivateKey(wrappedBase64, nonceBase64, password, saltBase64, E2eeKdfOptions.LegacyPbkdf2(iterations));

    public async Task<string> DecryptPrivateKey(
        string wrappedBase64, string nonceBase64, string password, string saltBase64, E2eeKdfOptions kdf)
    {
        var mod = await GetModule();
        return await mod.InvokeAsync<string>(
            "decryptPrivateKey", wrappedBase64, nonceBase64, password, saltBase64, kdf);
    }

    // ---- ECIES wrap/unwrap ----

    public async Task<(string EphemeralPublicKey, string Nonce, string Ciphertext, string Tag)>
        EcdhWrap(string masterKeyHandle, string recipientPublicKeyBase64)
    {
        var mod = await GetModule();
        var result = await mod.InvokeAsync<JsonElement>("ecdhWrap", masterKeyHandle, recipientPublicKeyBase64);
        return (
            result.GetProperty("ephemeralPublicKey").GetString()!,
            result.GetProperty("nonce").GetString()!,
            result.GetProperty("ciphertext").GetString()!,
            result.GetProperty("tag").GetString()!
        );
    }

    public async Task<string> EcdhUnwrap(
        string nonceBase64, string ciphertextBase64, string tagBase64,
        string ephemeralPublicKeyBase64, string privateKeyHandle)
    {
        var mod = await GetModule();
        return await mod.InvokeAsync<string>(
            "ecdhUnwrap", nonceBase64, ciphertextBase64, tagBase64,
            ephemeralPublicKeyBase64, privateKeyHandle);
    }

    // ---- Invitation key exchange ----

    public async Task<string> DeriveInvitationKey(string secretBase64)
    {
        var mod = await GetModule();
        return await mod.InvokeAsync<string>("deriveInvitationKey", secretBase64);
    }

    public async Task<(string Nonce, string Ciphertext)> EncryptForInvitation(
        string dataBase64, string invitationKeyHandle)
    {
        var mod = await GetModule();
        var result = await mod.InvokeAsync<JsonElement>(
            "encryptForInvitation", dataBase64, invitationKeyHandle);
        return (result.GetProperty("nonce").GetString()!,
                result.GetProperty("ciphertext").GetString()!);
    }

    public async Task<string> DecryptFromInvitation(
        string ciphertextBase64, string nonceBase64, string invitationKeyHandle)
    {
        var mod = await GetModule();
        return await mod.InvokeAsync<string>(
            "decryptFromInvitation", ciphertextBase64, nonceBase64, invitationKeyHandle);
    }
}

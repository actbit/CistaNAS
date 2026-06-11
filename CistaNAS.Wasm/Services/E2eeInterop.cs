using System.Text.Json;
using Microsoft.JSInterop;

namespace CistaNAS.Wasm.Services;

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

    /// <summary>PBKDF2 で KEK を導出し、JS 側にキャッシュしてハンドルを返す。</summary>
    /// <param name="username">クロスプラットフォーム互換のため SHA256(username) をソルトに混入（VolumeHeader.DeriveKek と統一）。</param>
    public async Task<string> DeriveKek(string password, string saltBase64, int iterations, string? username = null)
    {
        var mod = await GetModule();
        return await mod.InvokeAsync<string>("deriveKek", password, saltBase64, iterations, username as object);
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

    public async Task<string> EncryptChunk(byte[] plainBytes, string masterKeyHandle, int chunkIndex, string fileSaltBase64, bool isFirstChunk)
    {
        var mod = await GetModule();
        string plainBase64 = Convert.ToBase64String(plainBytes);
        return await mod.InvokeAsync<string>("encryptChunk", plainBase64, masterKeyHandle, chunkIndex, fileSaltBase64, isFirstChunk);
    }

    public async Task<byte[]> DecryptChunk(string encBase64, string masterKeyHandle, int chunkIndex, string fileSaltBase64)
    {
        var mod = await GetModule();
        string plainBase64 = await mod.InvokeAsync<string>("decryptChunk", encBase64, masterKeyHandle, chunkIndex, fileSaltBase64);
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

    public async Task<(string Nonce, string Wrapped)> EncryptPrivateKey(
        string privateKeyHandle, string password, string saltBase64, int iterations)
    {
        var mod = await GetModule();
        var result = await mod.InvokeAsync<JsonElement>(
            "encryptPrivateKey", privateKeyHandle, password, saltBase64, iterations);
        return (result.GetProperty("nonce").GetString()!,
                result.GetProperty("wrapped").GetString()!);
    }

    public async Task<string> DecryptPrivateKey(
        string wrappedBase64, string nonceBase64, string password, string saltBase64, int iterations)
    {
        var mod = await GetModule();
        return await mod.InvokeAsync<string>(
            "decryptPrivateKey", wrappedBase64, nonceBase64, password, saltBase64, iterations);
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

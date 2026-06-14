using System.Security.Cryptography;
using System.Text.Json;
using CistaNAS.Shared.Crypto;
using CistaNAS.Web.Services;
using CistaNAS.Web.Volume;
using Microsoft.Extensions.DependencyInjection;

namespace CistaNAS.Tests;

public class ClientE2eeRoundtripTests : IAsyncDisposable
{
    private readonly string _dataRoot;
    private readonly IServiceProvider _sp;
    private readonly VolumeService _vs;

    public ClientE2eeRoundtripTests()
    {
        (_sp, _dataRoot) = TestHelper.BuildTestServices();
        _vs = _sp.GetRequiredService<VolumeService>();
    }

    [Fact]
    public async Task FullRoundtrip_WrapOnServer_UnwrapOnClient_EncryptDecryptFile()
    {
        string username = "alice";
        string password = "test-password-123";
        string volName = "roundtrip-vol";

        // --- サーバー側: E2EE ボリューム作成 ---
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek(username, password, salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);
        CryptographicOperations.ZeroMemory(kek);

        var wrappedKey = new VolumeHeader.UserWrappedKey
        {
            WrapType = "password",
            Kdf = new() { Algorithm = "pbkdf2-sha256", Iterations = 1000, Salt = salt },
            WrappedMasterKey = new()
            {
                Algorithm = "aes-256-gcm",
                Nonce = nonce,
                Ciphertext = ct,
                Tag = tag,
            },
        };

        await _vs.CreateE2eeAsync(volName, username, wrappedKey);

        // --- クライアント側: VolumeHeader から wrapped key を取得 ---
        var header = await _vs.GetVolumeHeaderAsync(volName);
        var userKey = header.UserKeys[username];

        // --- クライアント側: KEK 導出 → マスターキー アンラップ ---
        byte[] clientKek = E2eeCrypto.DeriveKek(username, password,
            userKey.Kdf.Salt, userKey.Kdf.Iterations);
        byte[] clientMasterKey = E2eeCrypto.UnwrapMasterKey(
            userKey.WrappedMasterKey.Nonce,
            userKey.WrappedMasterKey.Ciphertext,
            userKey.WrappedMasterKey.Tag,
            clientKek);
        CryptographicOperations.ZeroMemory(clientKek);

        // マスターキーが一致することを確認
        Assert.Equal(masterKey, clientMasterKey);

        // --- クライアント側: ファイル暗号化/復号 ラウンドトリップ ---
        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(clientMasterKey, fileSalt);

        byte[] plainChunk0 = RandomNumberGenerator.GetBytes(1048576);
        byte[] plainChunk1 = RandomNumberGenerator.GetBytes(500000);

        byte[] encChunk0 = E2eeCrypto.EncryptChunk(plainChunk0, fileKey, 0, fileSalt, isFirstChunk: true);
        byte[] encChunk1 = E2eeCrypto.EncryptChunk(plainChunk1, fileKey, 1, fileSalt, isFirstChunk: false);

        byte[] decChunk0 = E2eeCrypto.DecryptChunk(encChunk0, fileKey, 0, out var extractedSalt);
        Assert.Equal(fileSalt, extractedSalt);
        Assert.Equal(plainChunk0, decChunk0);

        // チャンク1の復号にはfileSaltが必要
        byte[] decChunk1 = E2eeCrypto.DecryptChunk(encChunk1, fileKey, 1, fileSalt);
        Assert.Equal(plainChunk1, decChunk1);

        CryptographicOperations.ZeroMemory(clientMasterKey);
    }

    [Fact]
    public void FilenameEncryption_Roundtrip()
    {
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        string plainName = "日本語ファイル名_2025-01-15.txt";

        string encName = E2eeCrypto.EncryptFilename(plainName, masterKey);
        Assert.NotEqual(plainName, encName);

        string decName = E2eeCrypto.DecryptFilename(encName, masterKey);
        Assert.Equal(plainName, decName);
    }

    [Fact]
    public void WrappedKeySerialization_FromServerFormat()
    {
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek("user", "pw", salt, 1000);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(masterKey, kek);

        // サーバーから返される JSON 形式をシミュレート
        var serverResponse = new
        {
            kdf = new { algorithm = "pbkdf2-sha256", iterations = 1000, salt = Convert.ToBase64String(salt) },
            wrappedMasterKey = new
            {
                algorithm = "aes-256-gcm",
                nonce = Convert.ToBase64String(nonce),
                ciphertext = Convert.ToBase64String(ct),
                tag = Convert.ToBase64String(tag),
            },
        };

        string json = JsonSerializer.Serialize(serverResponse);
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        // クライアント側で JSON から復元
        byte[] rSalt = Convert.FromBase64String(root.GetProperty("kdf").GetProperty("salt").GetString()!);
        int rIter = root.GetProperty("kdf").GetProperty("iterations").GetInt32();
        byte[] rNonce = Convert.FromBase64String(root.GetProperty("wrappedMasterKey").GetProperty("nonce").GetString()!);
        byte[] rCt = Convert.FromBase64String(root.GetProperty("wrappedMasterKey").GetProperty("ciphertext").GetString()!);
        byte[] rTag = Convert.FromBase64String(root.GetProperty("wrappedMasterKey").GetProperty("tag").GetString()!);

        byte[] clientKek = E2eeCrypto.DeriveKek("user", "pw", rSalt, rIter);
        byte[] clientMasterKey = E2eeCrypto.UnwrapMasterKey(rNonce, rCt, rTag, clientKek);

        Assert.Equal(masterKey, clientMasterKey);
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var v in await _vs.ListAllAsync())
        {
            try
            {
                var header = await _vs.GetVolumeHeaderAsync(v.Name);
                await _vs.LockAsync(v.Name, header.OwnerUser);
            }
            catch (Exception) { }
        }
        try { if (Directory.Exists(_dataRoot)) Directory.Delete(_dataRoot, recursive: true); } catch (Exception) { }
    }
}

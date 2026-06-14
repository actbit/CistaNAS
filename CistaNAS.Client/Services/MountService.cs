using System.Collections.Concurrent;
using System.Security.Cryptography;
using CistaNAS.Client.Api;
using CistaNAS.Shared.Crypto;
using DokanNet;

namespace CistaNAS.Client.Services;

public sealed class MountService
{
    private readonly ConcurrentDictionary<string, MountedVolume> _mounted = new(StringComparer.Ordinal);

    /// <summary>
    /// E2EE ボリュームをマウントする。サーバー側マウント + クライアント側でマスターキー復号。
    /// </summary>
    public async Task MountE2eeAsync(string volumeName, string driveLetter, CistaNasApiClient api,
        string username, string password)
    {
        if (_mounted.ContainsKey(volumeName))
            throw new InvalidOperationException($"ボリューム '{volumeName}' は既にマウントされています。");

        // E2EE ボリュームのサーバー側マウント（アクセス権チェック）
        await api.MountAsync(volumeName);

        // サーバーから wrapped key 情報を取得
        var wkInfo = await api.GetWrappedKeyAsync(volumeName, username);

        byte[] masterKey;
        if (string.Equals(wkInfo.WrapType, "ecdh", StringComparison.OrdinalIgnoreCase))
        {
            // ECDH ラップキー: 自分の秘密鍵（DPAPI 永続化）で ECIES アンラップ。password 不要。
            byte[]? privateKey = EcdhKeyStore.LoadPrivateKey(username);
            if (privateKey is null)
                throw new InvalidOperationException(
                    "ローカルに ECDH 秘密鍵が見つかりません。先に設定で鍵ペアを生成してください。");
            if (wkInfo.EphemeralPublicKey is null)
                throw new InvalidOperationException("ECDH ラップキーに一時公開鍵が含まれていません。");
            try
            {
                masterKey = E2eeCrypto.EcdhUnwrap(
                    wkInfo.WrappedNonce, wkInfo.WrappedCiphertext, wkInfo.WrappedTag,
                    wkInfo.EphemeralPublicKey, privateKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(privateKey);
            }
        }
        else
        {
            // password ラップキー: KEK を導出してアンラップ
            byte[] kek = E2eeCrypto.DeriveKek(username, password, wkInfo.KdfSalt, wkInfo.KdfIterations);
            try
            {
                masterKey = E2eeCrypto.UnwrapMasterKey(
                    wkInfo.WrappedNonce, wkInfo.WrappedCiphertext, wkInfo.WrappedTag, kek);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(kek);
            }
        }

        var fs = new CistaNasFileSystem(api, masterKey, volumeName, wkInfo.ChunkSize);
        await MountDokanAsync(volumeName, driveLetter, fs, masterKey);
    }

    /// <summary>
    /// サーバー暗号化ボリュームをマウントする。サーバー側で復号されるためクライアント側鍵不要。
    /// </summary>
    public async Task MountServerAsync(string volumeName, string driveLetter, CistaNasApiClient api,
        string username, string password)
    {
        if (_mounted.ContainsKey(volumeName))
            throw new InvalidOperationException($"ボリューム '{volumeName}' は既にマウントされています。");

        // サーバー側マウント
        await CistaNasApiClientVolumes.MountVolumeAsync(api, volumeName, password);

        var fs = new CistaNasFileSystem(api, volumeName);
        await MountDokanAsync(volumeName, driveLetter, fs, null);
    }

    /// <summary>
    /// 平文（暗号化なし）ボリュームをマウントする。
    /// </summary>
    public async Task MountPlainAsync(string volumeName, string driveLetter, CistaNasApiClient api)
    {
        if (_mounted.ContainsKey(volumeName))
            throw new InvalidOperationException($"ボリューム '{volumeName}' は既にマウントされています。");

        // サーバー側マウント（パスワードなし）
        await CistaNasApiClientVolumes.MountVolumeAsync(api, volumeName, "");

        var fs = new CistaNasFileSystem(api, volumeName);
        await MountDokanAsync(volumeName, driveLetter, fs, null);
    }

    private async Task MountDokanAsync(string volumeName, string driveLetter, CistaNasFileSystem fs, byte[]? masterKey)
    {
        var cts = new CancellationTokenSource();
        var task = Task.Run(() =>
        {
            try
            {
                var dokan = new DokanNet.Dokan(logger: null!);
                var builder = new DokanInstanceBuilder(dokan)
                    .ConfigureOptions(options =>
                    {
                        options.MountPoint = driveLetter;
                        options.Options = DokanOptions.FixedDrive | DokanOptions.MountManager;
                        options.TimeOut = TimeSpan.FromMilliseconds(10000);
                        options.Version = DokanInstanceBuilder.DOKAN_VERSION;
                    });

                using var instance = builder.Build(fs);
                _mounted[volumeName] = new MountedVolume(driveLetter, instance, cts, masterKey);
                instance.WaitForFileSystemClosed(uint.MaxValue);
            }
            finally
            {
                _mounted.TryRemove(volumeName, out _);
            }
        }, cts.Token);

        await Task.Delay(1000);

        if (!_mounted.ContainsKey(volumeName))
            throw new InvalidOperationException("マウントに失敗しました。");
    }

    public async Task UnmountAsync(string volumeName)
    {
        if (!_mounted.TryRemove(volumeName, out var mv))
            throw new InvalidOperationException($"ボリューム '{volumeName}' はマウントされていません。");

        new DokanNet.Dokan(logger: null!).RemoveMountPoint(mv.DriveLetter);
        mv.Cts.Cancel();
        if (mv.MasterKey is not null)
            CryptographicOperations.ZeroMemory(mv.MasterKey);

        await Task.CompletedTask;
    }

    public bool IsMounted(string volumeName) => _mounted.ContainsKey(volumeName);

    public string? GetMountPoint(string volumeName)
        => _mounted.TryGetValue(volumeName, out var mv) ? mv.DriveLetter : null;

    private sealed class MountedVolume(string driveLetter, DokanInstance instance, CancellationTokenSource cts, byte[]? masterKey)
    {
        public string DriveLetter { get; } = driveLetter;
        public DokanInstance Instance { get; } = instance;
        public CancellationTokenSource Cts { get; } = cts;
        public byte[]? MasterKey { get; } = masterKey;
    }
}

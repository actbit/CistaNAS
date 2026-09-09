using System.Collections.Concurrent;
using System.Security.Cryptography;
using CistaNAS.Client.Api;
using CistaNAS.Client.Security;
using CistaNAS.Shared.Crypto;
using DokanNet;

namespace CistaNAS.Client.Services;

public sealed class MountService
{
    private readonly ConcurrentDictionary<string, MountedVolume> _mounted = new(StringComparer.Ordinal);

    /// <summary>
    /// E2EE ボリュームをマウントする。サーバー側マウント + クライアント側で鍵復号。
    /// 共有 v2 ボリューム（KeyEpoch ≥ 1）では全 epoch の GroupKey を自分の ECDH 秘密鍵で
    /// アンラップして v2 状態として登録する。オーナー（password wrap）のみ残置 v1 ファイルの
    /// 読み取り用に masterKey も復元する（v2 メンバーの wrapped-key は GroupKey wrap と同型のため
    /// masterKey としては扱わない）。
    /// </summary>
    public async Task MountE2eeAsync(string volumeName, string driveLetter, CistaNasApiClient api,
        string username, string password)
    {
        if (_mounted.ContainsKey(volumeName))
            throw new InvalidOperationException($"ボリューム '{volumeName}' は既にマウントされています。");

        // E2EE ボリュームのサーバー側マウント（アクセス権チェック）
        await api.MountAsync(volumeName);

        // 共有 v2: GroupKey wraps を取得してアンラップ（KeyEpoch ≥ 1 が v2 ボリューム）
        var gki = await api.GetGroupKeyInfoAsync(volumeName);
        if (gki is not null && gki.KeyEpoch >= 1)
        {
            E2eeV2VolumeState? v2 = await UnwrapGroupKeysV2Async(gki, username);
            try
            {
                // オーナー + password wrap の場合のみ masterKey も復元（残置 v1 ファイルの読み取り用）
                var wkInfo = await api.GetWrappedKeyAsync(volumeName, username);
                bool passwordWrap = wkInfo.WrapType is null
                    || string.Equals(wkInfo.WrapType, "password", StringComparison.OrdinalIgnoreCase);
                if (passwordWrap)
                {
                    byte[] masterKey = UnwrapPasswordWrappedKey(wkInfo, username, password);
                    try
                    {
                        var fs = new CistaNasFileSystem(api, masterKey, volumeName, wkInfo.ChunkSize, v2);
                        v2 = null; // 所有権をファイルシステムに移す
                        await MountDokanAsync(volumeName, driveLetter, fs);
                        return;
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(masterKey);
                    }
                }

                var fsMember = new CistaNasFileSystem(api, masterKey: null, volumeName, chunkSize: 1048576, v2);
                v2 = null; // 所有権をファイルシステムに移す
                await MountDokanAsync(volumeName, driveLetter, fsMember);
            }
            finally
            {
                v2?.Dispose();
            }
        }

        // v1 パス（従来方式）
        var wkV1 = await api.GetWrappedKeyAsync(volumeName, username);
        byte[] masterKeyV1;
        if (string.Equals(wkV1.WrapType, "ecdh", StringComparison.OrdinalIgnoreCase))
        {
            // ECDH ラップキー: 自分の秘密鍵（DPAPI 永続化）で ECIES アンラップ。password 不要。
            byte[]? privateKey = EcdhKeyStore.LoadPrivateKey(username);
            if (privateKey is null)
                throw new InvalidOperationException(
                    "ローカルに ECDH 秘密鍵が見つかりません。先に設定で鍵ペアを生成してください。");
            if (wkV1.EphemeralPublicKey is null)
                throw new InvalidOperationException("ECDH ラップキーに一時公開鍵が含まれていません。");
            try
            {
                using var privBuf = new SecureBuffer(privateKey);
                masterKeyV1 = E2eeCrypto.EcdhUnwrap(
                    wkV1.WrappedNonce, wkV1.WrappedCiphertext, wkV1.WrappedTag,
                    wkV1.EphemeralPublicKey, privBuf.Buffer);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(privateKey);
            }
        }
        else
        {
            masterKeyV1 = UnwrapPasswordWrappedKey(wkV1, username, password);
        }

        var fsV1 = new CistaNasFileSystem(api, masterKeyV1, volumeName, wkV1.ChunkSize);
        await MountDokanAsync(volumeName, driveLetter, fsV1);
    }

    /// <summary>共有 v2: 自分宛ての全 epoch GroupKey wraps を ECDH 秘密鍵でアンラップする。</summary>
    private static async Task<E2eeV2VolumeState> UnwrapGroupKeysV2Async(E2eeGroupKeyInfo gki, string username)
    {
        byte[]? privateKey = EcdhKeyStore.LoadPrivateKey(username);
        if (privateKey is null)
            throw new InvalidOperationException(
                "ローカルに ECDH 秘密鍵が見つかりません。先に設定で鍵ペアを生成してください。");
        try
        {
            var groupKeys = new Dictionary<int, byte[]>();
            foreach (var wrap in gki.MyGroupKeys)
            {
                if (wrap.EphemeralPublicKey is null) continue;
                try
                {
                    groupKeys[wrap.Epoch] = E2eeV2.EcdhUnwrapGroupKey(wrap.Nonce, wrap.Ciphertext, wrap.Tag,
                        wrap.EphemeralPublicKey, privateKey, gki.VolumeId, wrap.Epoch, username);
                }
                catch (System.Security.Cryptography.CryptographicException)
                {
                    // 個別 epoch のアンラップ失敗は無視（他の epoch で読めるファイルがある）
                }
            }
            if (groupKeys.Count == 0)
                throw new InvalidOperationException(
                    "共有 v2 の GroupKey を復号できませんでした（この共有から削除された可能性があります）。");
            return new E2eeV2VolumeState(gki.VolumeId, groupKeys);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
    }

    /// <summary>password ラップキーをヘッダの KDF スペック（Argon2id 合成 / レガシー PBKDF2）でアンラップする。</summary>
    private static byte[] UnwrapPasswordWrappedKey(WrappedKeyInfo wk, string username, string password)
    {
        byte[] kek = E2eeCrypto.DeriveKek(username, password, wk.KdfSalt, new KdfSpec(
            wk.KdfAlgorithm, wk.KdfIterations, wk.KdfMemoryKiB, wk.KdfParallelism, wk.KdfTimeCost));
        try
        {
            using var kekBuf = new SecureBuffer(kek);
            return E2eeCrypto.UnwrapMasterKey(
                wk.WrappedNonce, wk.WrappedCiphertext, wk.WrappedTag, kekBuf.Buffer);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
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
        await MountDokanAsync(volumeName, driveLetter, fs);
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
        await MountDokanAsync(volumeName, driveLetter, fs);
    }

    private async Task MountDokanAsync(string volumeName, string driveLetter, CistaNasFileSystem fs)
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
                _mounted[volumeName] = new MountedVolume(driveLetter, instance, cts, fs);
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
        mv.Fs.Dispose(); // マスターキー（VirtualUnlock 含む）・ファイルキー・平文チャンクをゼロクリア

        await Task.CompletedTask;
    }

    public bool IsMounted(string volumeName) => _mounted.ContainsKey(volumeName);

    public string? GetMountPoint(string volumeName)
        => _mounted.TryGetValue(volumeName, out var mv) ? mv.DriveLetter : null;

    private sealed class MountedVolume(string driveLetter, DokanInstance instance, CancellationTokenSource cts, CistaNasFileSystem fs)
    {
        public string DriveLetter { get; } = driveLetter;
        public DokanInstance Instance { get; } = instance;
        public CancellationTokenSource Cts { get; } = cts;
        public CistaNasFileSystem Fs { get; } = fs;
    }
}

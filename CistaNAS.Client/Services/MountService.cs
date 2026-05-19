using System.Collections.Concurrent;
using System.Security.Cryptography;
using CistaNAS.Client.Api;
using CistaNAS.Client.Crypto;
using DokanNet;

namespace CistaNAS.Client.Services;

public sealed class MountService
{
    private readonly ConcurrentDictionary<string, MountedVolume> _mounted = new(StringComparer.Ordinal);

    public async Task MountAsync(string volumeName, string driveLetter, CistaNasApiClient api, string password)
    {
        if (_mounted.ContainsKey(volumeName))
            throw new InvalidOperationException($"ボリューム '{volumeName}' は既にマウントされています。");

        byte[] salt = new byte[16]; // TODO: サーバーから取得
        byte[] kek = E2eeCrypto.DeriveKek("", password, salt, 310_000);
        byte[] masterKey = E2eeCrypto.GenerateMasterKey(); // TODO: サーバーから wrapped key を取得してアンラップ

        var fs = new CistaNasFileSystem(api, masterKey, volumeName);

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

        // マウントが完了するまで少し待つ
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
        CryptographicOperations.ZeroMemory(mv.MasterKey);

        await Task.CompletedTask;
    }

    public bool IsMounted(string volumeName) => _mounted.ContainsKey(volumeName);

    public string? GetMountPoint(string volumeName)
        => _mounted.TryGetValue(volumeName, out var mv) ? mv.DriveLetter : null;

    private sealed class MountedVolume(string driveLetter, DokanInstance instance, CancellationTokenSource cts, byte[] masterKey)
    {
        public string DriveLetter { get; } = driveLetter;
        public DokanInstance Instance { get; } = instance;
        public CancellationTokenSource Cts { get; } = cts;
        public byte[] MasterKey { get; } = masterKey;
    }
}

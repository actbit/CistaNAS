using CistaNAS.Client.Api;
using CistaNAS.Client.Crypto;
using DokanNet;

namespace CistaNAS.Client;

class Program
{
    static async Task<int> Main(string[] args)
    {
        if (args.Length < 4)
        {
            Console.WriteLine("Usage: CistaNAS.Client <serverUrl> <username> <password> <mountPoint> [volumeName]");
            Console.WriteLine("Example: CistaNAS.Client https://localhost:5001 admin mypassword Z: my-e2ee-vol");
            return 1;
        }

        string serverUrl = args[0].TrimEnd('/');
        string username = args[1];
        string password = args[2];
        string mountPoint = args[3];
        string volumeName = args.Length > 4 ? args[4] : "default";

        Console.WriteLine($"CistaNAS E2EE Client");
        Console.WriteLine($"Server: {serverUrl}");
        Console.WriteLine($"User: {username}");
        Console.WriteLine($"Mount: {mountPoint}");
        Console.WriteLine($"Volume: {volumeName}");

        var http = new HttpClient { BaseAddress = new Uri(serverUrl) };
        var api = new CistaNasApiClient(http);

        // ログイン
        Console.Write("Logging in... ");
        string token = await api.LoginAsync(username, password);
        api.SetToken(token);
        Console.WriteLine("OK");

        // マウント
        Console.Write("Mounting volume... ");
        await api.MountAsync(volumeName);
        Console.WriteLine("OK");

        // マスターキー導出（クライアント側のみ）
        // TODO: サーバーから KDF params + wrapped key を取得する API を追加
        byte[] salt = new byte[16]; // 実際はサーバーから取得
        byte[] kek = E2eeCrypto.DeriveKek(username, password, salt, 310_000);
        byte[] masterKey = E2eeCrypto.GenerateMasterKey(); // 仮

        var fs = new CistaNasFileSystem(api, masterKey, volumeName);

        Console.WriteLine($"Mounting at {mountPoint}... Press Ctrl+C to unmount.");

        try
        {
            var dokan = new DokanNet.Dokan(logger: null!);
            var builder = new DokanInstanceBuilder(dokan)
                .ConfigureOptions(options =>
                {
                    options.MountPoint = mountPoint;
                    options.Options = DokanOptions.FixedDrive | DokanOptions.MountManager;
                    options.TimeOut = TimeSpan.FromMilliseconds(10000);
                    options.Version = DokanInstanceBuilder.DOKAN_VERSION;
                });

            using var instance = builder.Build(fs);
            instance.WaitForFileSystemClosed(uint.MaxValue);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Mount failed: {ex.Message}");
            Console.Error.WriteLine("Ensure Dokan driver is installed.");
            return 1;
        }

        return 0;
    }
}

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CistaNAS.Web.Configuration;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.Services;

/// <summary>
/// 暗号化関連設定 (appsettings.json の CistaNas:Volume セクション) の永続化サービス (H-6)。
///
/// 旧実装は Pages/Settings.razor が直接 appsettings.json を読み書きしており、
/// コンテナ環境でのバインドマウント上書き・プロセス再起動未反映・フォーマット劣化
/// の問題があった。本サービスでは DataRoot 配下の "cista-settings.json" に
/// ユーザー設定を保存し、起動時に自動ロードする。
/// </summary>
public sealed class EncryptionSettingsService
{
    private readonly CistaNasOptions _options;
    private readonly ILogger<EncryptionSettingsService> _logger;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public EncryptionSettingsService(IOptions<CistaNasOptions> options, ILogger<EncryptionSettingsService> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    /// <summary>設定ファイルのパス。DataRoot 配下。</summary>
    private string SettingsPath => Path.Combine(_options.DataRoot, "cista-settings.json");

    /// <summary>現在の暗号化設定（メモリ上の CistaNasOptions）を返す。</summary>
    public VolumeOptions CurrentVolumeOptions() => _options.Volume;

    /// <summary>現在の認証設定（メモリ上の CistaNasOptions）を返す。</summary>
    public AuthOptions CurrentAuthOptions() => _options.Auth;

    /// <summary>
    /// DataRoot/cista-settings.json から VolumeOptions を読み込み、メモリ上の
    /// CistaNasOptions.Volume を更新する。ファイルが無ければ何もしない。
    /// </summary>
    public void LoadFromDiskIfExists()
    {
        if (!File.Exists(SettingsPath)) return;
        try
        {
            string json = File.ReadAllText(SettingsPath);
            var persisted = JsonSerializer.Deserialize<PersistedSettings>(json, JsonOptions);
            if (persisted?.Volume is not null)
            {
                _options.Volume.SectorSize = persisted.Volume.SectorSize;
                _options.Volume.KdfIterations = persisted.Volume.KdfIterations;
                _options.Volume.DefaultEncryptionMode = persisted.Volume.DefaultEncryptionMode;
                _options.Volume.E2eeChunkSize = persisted.Volume.E2eeChunkSize;
                _options.Volume.ChunkStorage = persisted.Volume.ChunkStorage;
                _options.Volume.ServerChunkSize = persisted.Volume.ServerChunkSize;
            }
            if (persisted?.Auth is not null)
            {
                _options.Auth.DefaultAdminUser = persisted.Auth.DefaultAdminUser;
                _options.Auth.Pbkdf2Iterations = persisted.Auth.Pbkdf2Iterations;
                _options.Auth.WebDavPbkdf2Iterations = persisted.Auth.WebDavPbkdf2Iterations;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "cista-settings.json の読み込みに失敗しました。");
        }
    }

    /// <summary>VolumeOptions を cista-settings.json に保存する。</summary>
    public void SaveVolumeOptions(VolumeOptions volume)
    {
        try
        {
            Directory.CreateDirectory(_options.DataRoot);
            var persisted = LoadOrInitPersisted();
            persisted.Volume = new PersistedVolume
            {
                SectorSize = volume.SectorSize,
                KdfIterations = volume.KdfIterations,
                DefaultEncryptionMode = volume.DefaultEncryptionMode,
                E2eeChunkSize = volume.E2eeChunkSize,
                ChunkStorage = volume.ChunkStorage,
                ServerChunkSize = volume.ServerChunkSize,
            };
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(persisted, JsonOptions), new UTF8Encoding(false));
            // メモリ上も更新
            _options.Volume = volume;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "cista-settings.json への保存に失敗しました。");
            throw;
        }
    }

    /// <summary>AuthOptions を cista-settings.json に保存する。</summary>
    public void SaveAuthOptions(AuthOptions auth)
    {
        try
        {
            Directory.CreateDirectory(_options.DataRoot);
            var persisted = LoadOrInitPersisted();
            persisted.Auth = new PersistedAuth
            {
                DefaultAdminUser = auth.DefaultAdminUser,
                Pbkdf2Iterations = auth.Pbkdf2Iterations,
                WebDavPbkdf2Iterations = auth.WebDavPbkdf2Iterations,
            };
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(persisted, JsonOptions), new UTF8Encoding(false));
            _options.Auth = auth;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "cista-settings.json への保存に失敗しました。");
            throw;
        }
    }

    private PersistedSettings LoadOrInitPersisted()
    {
        if (File.Exists(SettingsPath))
        {
            try
            {
                return JsonSerializer.Deserialize<PersistedSettings>(File.ReadAllText(SettingsPath), JsonOptions)
                    ?? new PersistedSettings();
            }
            catch
            {
                return new PersistedSettings();
            }
        }
        return new PersistedSettings();
    }

    private sealed class PersistedSettings
    {
        public PersistedVolume? Volume { get; set; }
        public PersistedAuth? Auth { get; set; }
    }

    private sealed class PersistedVolume
    {
        public int SectorSize { get; set; }
        public int KdfIterations { get; set; }
        public string DefaultEncryptionMode { get; set; } = "server";
        public int E2eeChunkSize { get; set; }
        public string ChunkStorage { get; set; } = "local";
        public int ServerChunkSize { get; set; }
    }

    private sealed class PersistedAuth
    {
        public string DefaultAdminUser { get; set; } = "admin";
        public int Pbkdf2Iterations { get; set; }
        public int WebDavPbkdf2Iterations { get; set; }
    }
}

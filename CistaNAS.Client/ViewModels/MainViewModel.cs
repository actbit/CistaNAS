using System.Collections.ObjectModel;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using CistaNAS.Client.Api;
using CistaNAS.Client.Security;
using CistaNAS.Client.Services;
using CistaNAS.Shared.Crypto;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace CistaNAS.Client.ViewModels;

public partial class MainViewModel : ObservableObject
{
    // ---- ログイン ----
    [ObservableProperty] private string _serverUrl = "https://localhost:5001";
    [ObservableProperty] private string _username = "";
    [ObservableProperty] private string _password = "";
    [ObservableProperty] private bool _isLoggedIn;
    [ObservableProperty] private string _statusMessage = "サーバーに接続してください。";
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private bool _isAdmin;
    [ObservableProperty] private bool _hasUsers = true;
    [ObservableProperty] private int _selectedTabIndex;

    // ---- セットアップ ----
    [ObservableProperty] private string _setupUsername = "admin";
    [ObservableProperty] private string _setupPassword = "";
    [ObservableProperty] private string _setupConfirmPassword = "";

    // ---- ボリューム ----
    [ObservableProperty] private ObservableCollection<VolumeItem> _volumes = [];
    [ObservableProperty] private VolumeItem? _selectedVolume;
    [ObservableProperty] private string _createVolName = "";
    [ObservableProperty] private string _createVolPassword = "";
    [ObservableProperty] private bool _createVolEncrypted = true;
    [ObservableProperty] private string _createVolEncMode = "server";

    // マウント
    [ObservableProperty] private string _selectedDriveLetter = "Z:";
    [ObservableProperty] private string _volumePassword = "";
    [ObservableProperty] private bool _showMountDialog;

    // 共有
    [ObservableProperty] private bool _showShareDialog;
    [ObservableProperty] private string _grantUsername = "";
    [ObservableProperty] private string _grantPassword = "";
    [ObservableProperty] private string _grantGranterPassword = "";
    [ObservableProperty] private ObservableCollection<string> _authorizedUsers = [];
    [ObservableProperty] private ObservableCollection<string> _authorizedGroups = [];
    [ObservableProperty] private string _grantGroupName = "";

    // ECDH
    [ObservableProperty] private string _ecdhUsername = "";
    [ObservableProperty] private string _pinUsername = ""; // pin 更新（明示的な再信頼）対象ユーザー

    // ---- グループ ----
    [ObservableProperty] private ObservableCollection<GroupItem> _groups = [];
    [ObservableProperty] private GroupItem? _selectedGroup;
    [ObservableProperty] private string _newGroupName = "";
    [ObservableProperty] private string _addMemberName = "";

    // ---- ユーザー ----
    [ObservableProperty] private ObservableCollection<UserItem> _users = [];
    [ObservableProperty] private string _newUserUsername = "";
    [ObservableProperty] private string _newUserPassword = "";
    [ObservableProperty] private string _newUserRole = "user";

    // ---- 設定: パスワード変更 ----
    [ObservableProperty] private string _currentPw = "";
    [ObservableProperty] private string _newPw = "";
    [ObservableProperty] private string _confirmPw = "";

    // ---- 設定: 暗号化 ----
    [ObservableProperty] private EncryptionSettingsInfo? _encSettings;
    [ObservableProperty] private string _encDefaultMode = "server";
    [ObservableProperty] private int _encChunkSize = 1048576;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsKdfComposite))]
    private string _encKdfAlgorithm = KdfSpec.Argon2id;
    [ObservableProperty] private int _encKdfIterations = 600_000;
    [ObservableProperty] private int _encKdfMemoryKiB = 65536;
    [ObservableProperty] private int _encKdfTimeCost = 4;
    [ObservableProperty] private int _encKdfParallelism = 4;
    [ObservableProperty] private int _encSectorSize = 4096;

    /// <summary>KDF 種別 ComboBox（SelectedIndex バインディング用）の選択肢。</summary>
    public static readonly string[] KdfAlgorithmValues = [KdfSpec.Argon2id, KdfSpec.Argon2idRaw];

    [ObservableProperty]
    private int _encKdfAlgorithmIndex = 0;

    /// <summary>Argon2id 単独（argon2id-raw）ではない（= 合成 KDF）とき true。PBKDF2 反復数入力の有効化に使用。</summary>
    public bool IsKdfComposite => !string.Equals(EncKdfAlgorithm, KdfSpec.Argon2idRaw, StringComparison.Ordinal);

    partial void OnEncKdfAlgorithmChanged(string value)
    {
        // ComboBox 側の SelectedIndex を同期（未登録の値は合成に寄せる）
        _encKdfAlgorithmIndex = Math.Max(0, Array.IndexOf(KdfAlgorithmValues, value ?? KdfAlgorithmValues[0]));
    }

    partial void OnEncKdfAlgorithmIndexChanged(int value)
    {
        string alg = KdfAlgorithmValues[Math.Clamp(value, 0, KdfAlgorithmValues.Length - 1)];
        if (!string.Equals(EncKdfAlgorithm, alg, StringComparison.Ordinal))
            EncKdfAlgorithm = alg; // OnEncKdfAlgorithmChanged で index が再同期される（収束）
    }

    // ---- 設定: E2EE鍵ペア ----
    [ObservableProperty] private bool _hasPublicKey;
    [ObservableProperty] private string _keyPairPassword = "";

    // ---- 招待 ----
    [ObservableProperty] private string _inviteTargetUsername = "";
    [ObservableProperty] private ObservableCollection<InvitationItem> _invitations = [];
    [ObservableProperty] private string _invitationResult = "";

    public ObservableCollection<string> AvailableDrives { get; } = [];
    public ObservableCollection<GroupInfo> AvailableGroups { get; } = [];

    private CistaNasApiClient? _api;
    private HttpClient? _http;
    private readonly MountService _mountService = new();
    private string? _jwtToken;

    public MainViewModel()
    {
        for (char c = 'D'; c <= 'Z'; c++)
            AvailableDrives.Add($"{c}:");
    }

    // ================================================================
    // 初期化
    // ================================================================

    [RelayCommand]
    private async Task InitializeAsync()
    {
        try
        {
            var baseUrl = new Uri(ServerUrl.TrimEnd('/'));
            _http?.Dispose();
            _http = new HttpClient { BaseAddress = baseUrl, Timeout = TimeSpan.FromSeconds(10) };
            _api = new CistaNasApiClient(_http);
            HasUsers = await _api.HasAnyUsersAsync();
        }
        catch
        {
            HasUsers = true; // エラー時はセットアップ済みとみなす
        }
    }

    // ================================================================
    // セットアップ
    // ================================================================

    [RelayCommand]
    private async Task SetupAsync()
    {
        if (string.IsNullOrWhiteSpace(SetupUsername) || string.IsNullOrWhiteSpace(SetupPassword))
        {
            StatusMessage = "ユーザー名とパスワードは必須です。";
            return;
        }
        if (SetupPassword != SetupConfirmPassword)
        {
            StatusMessage = "パスワードが一致しません。";
            return;
        }

        IsBusy = true;
        StatusMessage = "セットアップ中...";
        try
        {
            var baseUrl = new Uri(ServerUrl.TrimEnd('/'));
            _http?.Dispose();
            _http = new HttpClient { BaseAddress = baseUrl, Timeout = TimeSpan.FromSeconds(10) };
            _api = new CistaNasApiClient(_http);

            var ok = await _api.SetupAsync(SetupUsername, SetupPassword);
            if (!ok)
            {
                StatusMessage = "既にセットアップ済みです。";
                return;
            }

            // 自動ログイン
            var token = await _api.LoginAsync(SetupUsername, SetupPassword);
            _api.SetToken(token);
            _jwtToken = token;
            Username = SetupUsername;
            IsLoggedIn = true;
            IsAdmin = true;
            HasUsers = true;
            StatusMessage = $"{SetupUsername} としてセットアップ完了。";
            await RefreshVolumesAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"セットアップ失敗: {ex.Message}";
        }
        finally { IsBusy = false; }
    }

    // ================================================================
    // ログイン
    // ================================================================

    [RelayCommand]
    private async Task LoginAsync()
    {
        IsBusy = true;
        StatusMessage = "ログイン中...";
        try
        {
            var baseUrl = new Uri(ServerUrl.TrimEnd('/'));
            if (_http is null || _http.BaseAddress!.GetLeftPart(UriPartial.Authority) != baseUrl.GetLeftPart(UriPartial.Authority))
            {
                _http?.Dispose();
                _http = new HttpClient { BaseAddress = baseUrl, Timeout = TimeSpan.FromSeconds(10) };
            }
            _api = new CistaNasApiClient(_http);
            string token = await _api.LoginAsync(Username, Password);
            _api.SetToken(token);
            _jwtToken = token;
            IsLoggedIn = true;
            StatusMessage = $"{Username} としてログインしました。";

            // admin 判定（JWT クレームから）
            try
            {
                var payload = token.Split('.')[1];
                var padding = new string('=', (4 - payload.Length % 4) % 4);
                var json = JsonSerializer.Deserialize<JsonElement>(
                    System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(payload + padding)));
                IsAdmin = json.TryGetProperty("role", out var role) && role.GetString() == "admin";
            }
            catch { IsAdmin = false; }

            await RefreshVolumesAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"ログイン失敗: {ex.Message}";
        }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private void Logout()
    {
        IsLoggedIn = false;
        IsAdmin = false;
        _api = null;
        _jwtToken = null;
        StatusMessage = "ログアウトしました。";
    }

    // ================================================================
    // ボリューム
    // ================================================================

    [RelayCommand]
    private async Task RefreshVolumesAsync()
    {
        if (_api is null) return;
        try
        {
            var vols = await _api.ListVolumesDetailAsync();
            Volumes = new ObservableCollection<VolumeItem>(
                vols.Select(v => new VolumeItem
                {
                    Name = v.Name,
                    EncryptionMode = v.EncryptionMode,
                    Encrypted = v.Encrypted,
                    IsMounted = _mountService.IsMounted(v.Name),
                    MountPoint = _mountService.GetMountPoint(v.Name) ?? "",
                    OwnerUser = v.OwnerUser,
                    IsHome = v.IsHome,
                    AuthorizedUsers = v.AuthorizedUsers,
                    AuthorizedGroups = v.AuthorizedGroups,
                }));
        }
        catch (Exception ex)
        {
            StatusMessage = $"一覧取得失敗: {ex.Message}";
        }
    }

    [RelayCommand]
    private async Task CreateVolumeAsync()
    {
        if (_api is null || string.IsNullOrWhiteSpace(CreateVolName)) return;
        IsBusy = true;
        StatusMessage = "ボリューム作成中...";
        try
        {
            if (CreateVolEncrypted && CreateVolEncMode == "e2ee")
            {
                await CreateE2eeVolumeAsync();
            }
            else if (CreateVolEncrypted && CreateVolEncMode == "group-e2ee")
            {
                await CreateGroupE2eeVolumeAsync();
            }
            else
            {
                await CistaNasApiClientVolumes.CreateVolumeAsync(_api,
                    CreateVolName, Username,
                    CreateVolEncrypted ? CreateVolPassword : null,
                    CreateVolEncrypted);
            }

            CreateVolName = "";
            CreateVolPassword = "";
            StatusMessage = "ボリュームを作成しました。";
            await RefreshVolumesAsync();
        }
        catch (Exception ex) { StatusMessage = $"作成失敗: {ex.Message}"; }
        finally { IsBusy = false; }
    }

    /// <summary>
    /// 新規 E2EE ボリュームの KEK 導出に使う KDF スペックをサーバー設定から取得する
    /// （Argon2id+PBKDF2 合成 or Argon2id 単独）。取得失敗時は現行標準にフォールバック。
    /// </summary>
    private async Task<KdfSpec> GetCreationKdfAsync()
    {
        try
        {
            var settings = await CistaNasApiClientSettings.GetEncryptionSettingsAsync(_api!);
            return ToKdfSpec(settings);
        }
        catch
        {
            return KdfSpec.DefaultArgon2id;
        }
    }

    private static KdfSpec ToKdfSpec(EncryptionSettingsInfo s) =>
        string.Equals(s.KdfAlgorithm, KdfSpec.Argon2idRaw, StringComparison.Ordinal)
            ? new KdfSpec(KdfSpec.Argon2idRaw, 0, s.KdfMemoryKiB, s.KdfParallelism, s.KdfTimeCost)
            : new KdfSpec(KdfSpec.Argon2id, s.KdfIterations, s.KdfMemoryKiB, s.KdfParallelism, s.KdfTimeCost);

    private static KdfInfo ToKdfInfo(KdfSpec spec) =>
        new(spec.Algorithm, spec.Iterations, spec.MemoryKiB, spec.TimeCost, spec.Parallelism);

    private async Task CreateE2eeVolumeAsync()
    {
        // サーバー設定の KDF 種別に従う（既定: Argon2id+PBKDF2 合成）
        KdfSpec spec = await GetCreationKdfAsync();
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        using var kekBuf = new SecureBuffer(E2eeCrypto.DeriveKek(Username!, CreateVolPassword, salt, spec));
        byte[] masterKey = new byte[32];
        RandomNumberGenerator.Fill(masterKey);
        using var mkBuf = new SecureBuffer(masterKey);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(mkBuf.Buffer, kekBuf.Buffer);

        await _api!.CreateVolumeAsync(CreateVolName, Username!, nonce, ct, tag, salt, ToKdfInfo(spec));
    }

    private async Task CreateGroupE2eeVolumeAsync()
    {
        // サーバー設定の KDF 種別に従う（既定: Argon2id+PBKDF2 合成）
        KdfSpec spec = await GetCreationKdfAsync();
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        using var kekBuf = new SecureBuffer(E2eeCrypto.DeriveKek(Username!, CreateVolPassword, salt, spec));
        byte[] masterKey = new byte[32];
        RandomNumberGenerator.Fill(masterKey);
        using var mkBuf = new SecureBuffer(masterKey);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(mkBuf.Buffer, kekBuf.Buffer);

        await CistaNasApiClientE2eeExtensions.CreateGroupVolumeAsync(_api!, CreateVolName, nonce, ct, tag, salt, ToKdfInfo(spec));
    }

    [RelayCommand]
    private async Task DeleteVolumeAsync()
    {
        if (_api is null || SelectedVolume is null) return;
        IsBusy = true;
        try
        {
            await CistaNasApiClientVolumes.DeleteVolumeAsync(_api, SelectedVolume.Name);
            StatusMessage = $"{SelectedVolume.Name} を削除しました。";
            await RefreshVolumesAsync();
        }
        catch (Exception ex) { StatusMessage = $"削除失敗: {ex.Message}"; }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private void ShowMount()
    {
        if (SelectedVolume is null) return;
        VolumePassword = "";
        ShowMountDialog = true;
    }

    [RelayCommand]
    private async Task MountAsync()
    {
        if (_api is null || SelectedVolume is null) return;
        IsBusy = true;
        StatusMessage = "マウント中...";
        try
        {
            if (SelectedVolume.IsE2ee)
            {
                await _mountService.MountE2eeAsync(SelectedVolume.Name, SelectedDriveLetter, _api, Username, VolumePassword);
            }
            else if (SelectedVolume.EncryptionMode == "server")
            {
                await _mountService.MountServerAsync(SelectedVolume.Name, SelectedDriveLetter, _api, Username, VolumePassword);
            }
            else
            {
                await _mountService.MountPlainAsync(SelectedVolume.Name, SelectedDriveLetter, _api);
            }

            StatusMessage = $"{SelectedVolume.Name} を {SelectedDriveLetter} にマウントしました。";
            ShowMountDialog = false;
            await RefreshVolumesAsync();
        }
        catch (Exception ex) { StatusMessage = $"マウント失敗: {ex.Message}"; }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task UnmountAsync()
    {
        if (SelectedVolume is null) return;
        IsBusy = true;
        StatusMessage = "アンマウント中...";
        try
        {
            await _mountService.UnmountAsync(SelectedVolume.Name);
            // サーバー側もロック
            if (_api is not null)
            {
                try { await CistaNasApiClientVolumes.LockVolumeAsync(_api, SelectedVolume.Name); } catch { }
            }
            StatusMessage = $"{SelectedVolume.Name} をアンマウントしました。";
            await RefreshVolumesAsync();
        }
        catch (Exception ex) { StatusMessage = $"アンマウント失敗: {ex.Message}"; }
        finally { IsBusy = false; }
    }

    // ---- 共有 ----

    [RelayCommand]
    private async Task ShowShare()
    {
        if (SelectedVolume is null || _api is null) return;
        AuthorizedUsers = new ObservableCollection<string>(SelectedVolume.AuthorizedUsers);
        AuthorizedGroups = new ObservableCollection<string>(SelectedVolume.AuthorizedGroups);
        GrantUsername = "";
        GrantPassword = "";
        GrantGranterPassword = "";
        EcdhUsername = "";
        GrantGroupName = "";

        // グループ一覧を取得
        AvailableGroups.Clear();
        try
        {
            var groups = await CistaNasApiClientGroups.ListGroupsAsync(_api);
            foreach (var g in groups)
                AvailableGroups.Add(g);
        }
        catch { }

        ShowShareDialog = true;
    }

    [RelayCommand]
    private async Task GrantAccess()
    {
        if (_api is null || SelectedVolume is null || string.IsNullOrWhiteSpace(GrantUsername)) return;
        try
        {
            await CistaNasApiClientVolumes.GrantAccessAsync(_api, SelectedVolume.Name, GrantGranterPassword, GrantUsername.Trim(), GrantPassword);
            StatusMessage = $"{GrantUsername} にアクセス権を付与しました。";
            GrantUsername = "";
            GrantPassword = "";
            GrantGranterPassword = "";
            await RefreshVolumesAsync();
            // 再表示
            if (SelectedVolume is not null)
                AuthorizedUsers = new ObservableCollection<string>(SelectedVolume.AuthorizedUsers);
        }
        catch (Exception ex) { StatusMessage = $"アクセス権付与失敗: {ex.Message}"; }
    }

    [RelayCommand]
    private async Task RevokeAccess(string targetUser)
    {
        if (_api is null || SelectedVolume is null) return;
        try
        {
            // 共有 v2 の E2EE オーナーによる剥奪は GroupKey ローテーションで行う:
            // 新 epoch の GroupKey は remaining members（削除対象を除く）宛てのみ生成され、
            // 削除対象の鍵はサーバーからも除去される（rotate-group-key が ACL 剥奪込みで処理）。
            // revoke 前のデータを削除対象が回収済みの可能性は防げない点に注意。
            bool revokedByRotation = false;
            if (SelectedVolume.IsE2ee
                && string.Equals(SelectedVolume.OwnerUser, Username, StringComparison.Ordinal))
            {
                var gki = await _api.GetGroupKeyInfoAsync(SelectedVolume.Name);
                if (gki is not null && gki.KeyEpoch >= 1)
                {
                    await RotateGroupKeyV2Async(SelectedVolume.Name, gki, targetUser);
                    revokedByRotation = true;
                    StatusMessage = $"{targetUser} のアクセス権を剥奪し、GroupKey をローテーションしました（epoch {gki.KeyEpoch + 1}）。";
                }
            }

            if (!revokedByRotation)
            {
                await CistaNasApiClientVolumes.RevokeAccessAsync(_api, SelectedVolume.Name, targetUser);
                StatusMessage = $"{targetUser} のアクセス権を剥奪しました。";
            }
            await RefreshVolumesAsync();
            if (SelectedVolume is not null)
                AuthorizedUsers = new ObservableCollection<string>(SelectedVolume.AuthorizedUsers);
        }
        catch (Exception ex) { StatusMessage = $"アクセス権剥奪失敗: {ex.Message}"; }
    }

    /// <summary>
    /// 共有 v2: 新 GroupKey を生成して remaining members（targetUser を除く全メンバー）の公開鍵で
    /// ECIES ラップし、rotate-group-key で epoch を進める（targetUser の鍵エントリと ACL はサーバー側で
    /// 全削除される）。ローテーション後、旧 epoch の per-file DEK を新 epoch GroupKey に再ラップする
    /// （チャンク本体は不変）。pin 不一致時は例外で中断（鍵の削除も行わない）。
    /// </summary>
    private async Task RotateGroupKeyV2Async(string volumeName, E2eeGroupKeyInfo gki, string targetUser)
    {
        int currentEpoch = gki.KeyEpoch;
        int newEpoch = currentEpoch + 1;
        string volumeId = gki.VolumeId;

        // 現行 epoch の GroupKey を自分の ECDH 秘密鍵でアンラップ（旧 per-file DEK の再ラップ用）
        var myWrap = gki.MyGroupKeys.FirstOrDefault(k => k.Epoch == currentEpoch)
            ?? throw new InvalidOperationException("自分宛ての現行 epoch GroupKey がありません。");
        byte[]? privateKey = EcdhKeyStore.LoadPrivateKey(Username!);
        if (privateKey is null)
            throw new InvalidOperationException("ローカルに ECDH 秘密鍵が見つかりません。先に設定で鍵ペアを生成してください。");
        try
        {
            using var oldGroupKeyBuf = new SecureBuffer(E2eeV2.EcdhUnwrapGroupKey(
                myWrap.Nonce, myWrap.Ciphertext, myWrap.Tag, myWrap.EphemeralPublicKey!,
                privateKey, volumeId, currentEpoch, Username!));

            // remaining members（削除対象を除く）の公開鍵を取得して pin 検証 → wrap 生成
            var members = (await _api!.GetMemberPublicKeysAsync(volumeName))
                .Where(m => !string.Equals(m.Username, targetUser, StringComparison.Ordinal))
                .ToList();
            if (members.Count == 0)
                throw new InvalidOperationException("remaining members がいません（自分宛ての wrap が少なくとも 1 つ必要です）。");

            byte[] newGroupKey = E2eeV2.GenerateGroupKey();
            try
            {
                var wraps = new Dictionary<string, (byte[] nonce, byte[] ct, byte[] tag, byte[] ephemeralPublicKey)>();
                foreach (var m in members)
                {
                    if (m.PublicKeyBase64 is null)
                        throw new InvalidOperationException($"ユーザー '{m.Username}' の公開鍵が未登録のため GroupKey をローテーションできません。");
                    byte[] pubRaw = Convert.FromBase64String(m.PublicKeyBase64);
                    if (!VerifyOrCreatePin(m.Username, pubRaw))
                        throw new InvalidOperationException(
                            $"{m.Username} の暗号化公開鍵が以前確認したものから変更されています。サーバー侵害または鍵更新の可能性があります。操作を中断しました。");
                    wraps[m.Username] = E2eeV2.EcdhWrapGroupKey(newGroupKey, pubRaw, volumeId, newEpoch, m.Username);
                }
                if (wraps.ContainsKey(targetUser))
                    throw new InvalidOperationException("削除対象ユーザー宛ての wrap が含まれています。");
                if (!wraps.ContainsKey(Username!))
                    throw new InvalidOperationException("自分宛ての wrap が含まれていません（オーナーは remaining members に含まれる必要があります）。");

                await _api!.RotateGroupKeyAsync(volumeName, newEpoch, wraps, removedUsername: targetUser);

                // 旧 epoch の per-file DEK を新 epoch GroupKey に再ラップしてサーバーに登録（チャンク本体は不変）。
                // v1 形式ファイル（KeyEpoch == 0）は対象外（オーナーの masterKey でのみ読めるまま）。
                var files = await _api!.ListFilesAsync(volumeName);
                var rewraps = new List<(string fileId, int keyEpoch, WrappedAeadKey wrappedFileKey)>();
                foreach (var f in files)
                {
                    if (f.KeyEpoch != currentEpoch || f.WrappedFileKey is null) continue;
                    byte[] dek = E2eeV2.UnwrapFileKey(f.WrappedFileKey.Nonce, f.WrappedFileKey.Ciphertext, f.WrappedFileKey.Tag,
                        oldGroupKeyBuf.Buffer, volumeId, f.FileId, f.KeyEpoch);
                    try
                    {
                        var (wNonce, wCt, wTag) = E2eeV2.WrapFileKey(dek, newGroupKey, volumeId, f.FileId, newEpoch);
                        rewraps.Add((f.FileId, newEpoch, new WrappedAeadKey
                        { Algorithm = "aes-256-gcm", Nonce = wNonce, Ciphertext = wCt, Tag = wTag }));
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(dek);
                    }
                }
                if (rewraps.Count > 0)
                    await _api.RewrapFileKeysAsync(volumeName, rewraps);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(newGroupKey);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
    }

    [RelayCommand]
    private async Task GrantGroup()
    {
        if (_api is null || SelectedVolume is null || string.IsNullOrWhiteSpace(GrantGroupName)) return;
        try
        {
            await CistaNasApiClientVolumes.GrantGroupAccessAsync(_api, SelectedVolume.Name, GrantGroupName);
            StatusMessage = $"グループ {GrantGroupName} にアクセス権を付与しました。";
            GrantGroupName = "";
            await RefreshVolumesAsync();
            if (SelectedVolume is not null)
                AuthorizedGroups = new ObservableCollection<string>(SelectedVolume.AuthorizedGroups);
        }
        catch (Exception ex) { StatusMessage = $"グループアクセス付与失敗: {ex.Message}"; }
    }

    [RelayCommand]
    private async Task RevokeGroup(string groupName)
    {
        if (_api is null || SelectedVolume is null) return;
        try
        {
            await CistaNasApiClientVolumes.RevokeGroupAccessAsync(_api, SelectedVolume.Name, groupName);
            StatusMessage = $"グループ {groupName} のアクセス権を剥奪しました。";
            await RefreshVolumesAsync();
            if (SelectedVolume is not null)
                AuthorizedGroups = new ObservableCollection<string>(SelectedVolume.AuthorizedGroups);
        }
        catch (Exception ex) { StatusMessage = $"グループアクセス剥奪失敗: {ex.Message}"; }
    }

    [RelayCommand]
    private async Task EcdhGrant()
    {
        if (_api is null || SelectedVolume is null || string.IsNullOrWhiteSpace(EcdhUsername)) return;
        IsBusy = true;
        try
        {
            string targetUser = EcdhUsername.Trim();

            // 相手の公開鍵を取得
            string? recipientPubKeyB64 = await CistaNasApiClientE2eeExtensions.GetPublicKeyAsync(_api, targetUser);
            if (recipientPubKeyB64 is null)
            {
                StatusMessage = "相手の公開鍵が登録されていません。";
                return;
            }
            byte[] recipientPubKeyRaw = Convert.FromBase64String(recipientPubKeyB64);

            // TOFU pin 検証: pin 未登録なら記録、不一致なら中断（自動的には新しい鍵を信頼しない）。
            if (!VerifyOrCreatePin(targetUser, recipientPubKeyRaw))
                return;

            // 共有 v2（GroupKey epoch 運用）: masterKey の代わりに現行 epoch GroupKey を
            // 新メンバーの公開鍵でラップする（rotation はしない — 追加メンバーは現行 epoch
            // 以降のデータのみ読める）。GroupKey の復号は ECDH 秘密鍵（DPAPI 保護）で行うため
            // パスワード不要。
            var gki = await _api.GetGroupKeyInfoAsync(SelectedVolume.Name);
            if (gki is not null && gki.KeyEpoch >= 1)
            {
                var myWrap = gki.MyGroupKeys.FirstOrDefault(k => k.Epoch == gki.KeyEpoch)
                    ?? throw new InvalidOperationException("自分宛ての現行 epoch GroupKey がありません。");
                byte[]? privateKey = EcdhKeyStore.LoadPrivateKey(Username!);
                if (privateKey is null)
                    throw new InvalidOperationException("ローカルに ECDH 秘密鍵が見つかりません。先に設定で鍵ペアを生成してください。");
                try
                {
                    using var groupKeyBuf = new SecureBuffer(E2eeV2.EcdhUnwrapGroupKey(
                        myWrap.Nonce, myWrap.Ciphertext, myWrap.Tag, myWrap.EphemeralPublicKey!,
                        privateKey, gki.VolumeId, gki.KeyEpoch, Username!));
                    var (ephPubKey, nonce, ct, tag) = E2eeV2.EcdhWrapGroupKey(
                        groupKeyBuf.Buffer, recipientPubKeyRaw, gki.VolumeId, gki.KeyEpoch, targetUser);
                    await CistaNasApiClientE2eeExtensions.AddWrappedKeyAsync(_api, SelectedVolume.Name, targetUser, nonce, ct, tag, ephPubKey);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(privateKey);
                }

                StatusMessage = $"{targetUser} に ECDH 共有しました（共有 v2）。";
                EcdhUsername = "";
                await RefreshVolumesAsync();
                return;
            }

            // v1: 自分の wrapped key を取得してアンラップ（従来フロー）
            var wkInfo = await _api.GetWrappedKeyAsync(SelectedVolume.Name, Username!);
            using var kekBuf = new SecureBuffer(E2eeCrypto.DeriveKek(Username!, GrantGranterPassword, wkInfo.KdfSalt, new KdfSpec(
                wkInfo.KdfAlgorithm, wkInfo.KdfIterations, wkInfo.KdfMemoryKiB, wkInfo.KdfParallelism, wkInfo.KdfTimeCost)));
            using var mkBuf = new SecureBuffer(E2eeCrypto.UnwrapMasterKey(wkInfo.WrappedNonce, wkInfo.WrappedCiphertext, wkInfo.WrappedTag, kekBuf.Buffer));

            // ECIES ラップ (E2eeCrypto を使用) - 相手公開鍵は raw 非圧縮点 65B
            var (ephPubKeyV1, nonceV1, ctV1, tagV1) = E2eeCrypto.EcdhWrap(mkBuf.Buffer, recipientPubKeyRaw);

            await CistaNasApiClientE2eeExtensions.AddWrappedKeyAsync(_api, SelectedVolume.Name, targetUser, nonceV1, ctV1, tagV1, ephPubKeyV1);
            StatusMessage = $"{targetUser} に ECDH 共有しました。";
            EcdhUsername = "";
            GrantGranterPassword = "";
            await RefreshVolumesAsync();
        }
        catch (Exception ex) { StatusMessage = $"ECDH 共有失敗: {ex.Message}"; }
        finally { IsBusy = false; }
    }

    /// <summary>
    /// TOFU pin 検証。pin 未登録なら fingerprint を記録して保存（初回使用）。
    /// 登録済みで fingerprint が一致しない場合は操作を中断して false を返す
    /// （自動的には新しい鍵を信頼しない。pin 更新は TrustNewKey コマンド = ユーザーの明示操作のみ）。
    /// pin はローカル（%APPDATA%）にのみ保存され、サーバーには送信されない。
    /// </summary>
    private bool VerifyOrCreatePin(string targetUser, byte[] recipientPubKeyRaw)
    {
        string fingerprint = E2eeV2.ComputeFingerprint(recipientPubKeyRaw);
        string? pinned = PublicKeyPinStore.GetPin(Username!, targetUser);
        if (pinned is null)
        {
            PublicKeyPinStore.SetPin(Username!, targetUser, fingerprint);
            return true;
        }
        if (!string.Equals(pinned, fingerprint, StringComparison.Ordinal))
        {
            StatusMessage = $"{targetUser} の暗号化公開鍵が以前確認したものから変更されています。" +
                "サーバー侵害または鍵更新の可能性があります。操作を中断しました。" +
                "本人確認のうえ「pin 更新」で明示的に再信頼してください。";
            return false;
        }
        return true;
    }

    /// <summary>pin 不一致検知後の明示的な pin 更新（新しい鍵を信頼する）。
    /// サーバーが現在公開している鍵を pin し直すのみで、中断した共有操作は自動再実行しない。</summary>
    [RelayCommand]
    private async Task TrustNewKey()
    {
        if (_api is null || string.IsNullOrWhiteSpace(PinUsername)) return;
        try
        {
            string targetUser = PinUsername.Trim();
            string? pubKeyB64 = await CistaNasApiClientE2eeExtensions.GetPublicKeyAsync(_api, targetUser);
            if (pubKeyB64 is null)
            {
                StatusMessage = $"{targetUser} の公開鍵が登録されていません。";
                return;
            }
            byte[] pubRaw = Convert.FromBase64String(pubKeyB64);
            PublicKeyPinStore.SetPin(Username!, targetUser, E2eeV2.ComputeFingerprint(pubRaw));
            StatusMessage = $"{targetUser} の公開鍵を再信頼しました（pin 更新）。";
            PinUsername = "";
        }
        catch (Exception ex) { StatusMessage = $"pin 更新失敗: {ex.Message}"; }
    }

    // ================================================================
    // グループ
    // ================================================================

    [RelayCommand]
    private async Task RefreshGroupsAsync()
    {
        if (_api is null) return;
        try
        {
            var groups = await CistaNasApiClientGroups.ListGroupsAsync(_api);
            Groups = new ObservableCollection<GroupItem>(
                groups.Select(g => new GroupItem
                {
                    GroupName = g.GroupName,
                    Owner = g.OwnerUsername,
                    Members = g.Members,
                }));
        }
        catch (Exception ex) { StatusMessage = $"グループ取得失敗: {ex.Message}"; }
    }

    [RelayCommand]
    private async Task CreateGroup()
    {
        if (_api is null || string.IsNullOrWhiteSpace(NewGroupName)) return;
        try
        {
            await CistaNasApiClientGroups.CreateGroupAsync(_api, NewGroupName.Trim());
            NewGroupName = "";
            StatusMessage = "グループを作成しました。";
            await RefreshGroupsAsync();
        }
        catch (Exception ex) { StatusMessage = $"グループ作成失敗: {ex.Message}"; }
    }

    [RelayCommand]
    private async Task DeleteGroup(string groupName)
    {
        if (_api is null) return;
        try
        {
            await CistaNasApiClientGroups.DeleteGroupAsync(_api, groupName);
            StatusMessage = $"グループ {groupName} を削除しました。";
            if (SelectedGroup?.GroupName == groupName) SelectedGroup = null;
            await RefreshGroupsAsync();
        }
        catch (Exception ex) { StatusMessage = $"グループ削除失敗: {ex.Message}"; }
    }

    [RelayCommand]
    private async Task AddMember()
    {
        if (_api is null || SelectedGroup is null || string.IsNullOrWhiteSpace(AddMemberName)) return;
        try
        {
            await CistaNasApiClientGroups.AddGroupMemberAsync(_api, SelectedGroup.GroupName, AddMemberName.Trim());
            AddMemberName = "";
            await RefreshGroupsAsync();
            // 再選択
            var g = Groups.FirstOrDefault(g => g.GroupName == SelectedGroup.GroupName);
            if (g is not null) SelectedGroup = g;
        }
        catch (Exception ex) { StatusMessage = $"メンバー追加失敗: {ex.Message}"; }
    }

    [RelayCommand]
    private async Task RemoveMember(string username)
    {
        if (_api is null || SelectedGroup is null) return;
        try
        {
            await CistaNasApiClientGroups.RemoveGroupMemberAsync(_api, SelectedGroup.GroupName, username);
            await RefreshGroupsAsync();
            var g = Groups.FirstOrDefault(g => g.GroupName == SelectedGroup?.GroupName);
            if (g is not null) SelectedGroup = g;
        }
        catch (Exception ex) { StatusMessage = $"メンバー削除失敗: {ex.Message}"; }
    }

    // ================================================================
    // ユーザー管理 (admin)
    // ================================================================

    [RelayCommand]
    private async Task RefreshUsersAsync()
    {
        if (_api is null || !IsAdmin) return;
        try
        {
            var users = await CistaNasApiClientAccount.ListUsersAsync(_api);
            Users = new ObservableCollection<UserItem>(
                users.Select(u => new UserItem
                {
                    UserName = u.UserName,
                    Roles = u.Roles,
                }));
        }
        catch (Exception ex) { StatusMessage = $"ユーザー一覧取得失敗: {ex.Message}"; }
    }

    [RelayCommand]
    private async Task CreateUser()
    {
        if (_api is null) return;
        try
        {
            await CistaNasApiClientAccount.CreateUserAsync(_api, NewUserUsername.Trim(), NewUserPassword, NewUserRole);
            NewUserUsername = "";
            NewUserPassword = "";
            NewUserRole = "user";
            StatusMessage = "ユーザーを作成しました。";
            await RefreshUsersAsync();
        }
        catch (Exception ex) { StatusMessage = $"ユーザー作成失敗: {ex.Message}"; }
    }

    [RelayCommand]
    private async Task DeleteUser(string username)
    {
        if (_api is null) return;
        try
        {
            await CistaNasApiClientAccount.DeleteUserAsync(_api, username);
            StatusMessage = $"ユーザー {username} を削除しました。";
            await RefreshUsersAsync();
        }
        catch (Exception ex) { StatusMessage = $"ユーザー削除失敗: {ex.Message}"; }
    }

    // ================================================================
    // 設定
    // ================================================================

    [RelayCommand]
    private async Task ChangePassword()
    {
        if (_api is null) return;
        if (NewPw != ConfirmPw)
        {
            StatusMessage = "新しいパスワードが一致しません。";
            return;
        }
        try
        {
            await CistaNasApiClientAuth.ChangePasswordAsync(_api, CurrentPw, NewPw);
            StatusMessage = "パスワードを変更しました。";
            CurrentPw = "";
            NewPw = "";
            ConfirmPw = "";
        }
        catch (Exception ex) { StatusMessage = $"パスワード変更失敗: {ex.Message}"; }
    }

    [RelayCommand]
    private async Task LoadEncryptionSettings()
    {
        if (_api is null) return;
        try
        {
            var settings = await CistaNasApiClientSettings.GetEncryptionSettingsAsync(_api);
            EncDefaultMode = settings.DefaultEncryptionMode;
            EncChunkSize = settings.E2eeChunkSize;
            EncKdfAlgorithm = settings.KdfAlgorithm;
            EncKdfIterations = settings.KdfIterations;
            EncKdfMemoryKiB = settings.KdfMemoryKiB;
            EncKdfTimeCost = settings.KdfTimeCost;
            EncKdfParallelism = settings.KdfParallelism;
            EncSectorSize = settings.SectorSize;
        }
        catch { }
    }

    [RelayCommand]
    private async Task SaveEncryptionSettings()
    {
        if (_api is null) return;
        try
        {
            var settings = new EncryptionSettingsInfo
            {
                DefaultEncryptionMode = EncDefaultMode,
                E2eeChunkSize = EncChunkSize,
                KdfAlgorithm = EncKdfAlgorithm,
                KdfIterations = EncKdfIterations,
                KdfMemoryKiB = EncKdfMemoryKiB,
                KdfTimeCost = EncKdfTimeCost,
                KdfParallelism = EncKdfParallelism,
                SectorSize = EncSectorSize,
            };
            await CistaNasApiClientSettings.SaveEncryptionSettingsAsync(_api, settings);
            StatusMessage = "暗号化設定を保存しました。";
        }
        catch (Exception ex) { StatusMessage = $"設定保存失敗: {ex.Message}"; }
    }

    [RelayCommand]
    private async Task GenerateKeyPair()
    {
        if (_api is null || string.IsNullOrWhiteSpace(Username)) return;
        IsBusy = true;
        try
        {
            // ECDH P-256 鍵ペア生成（公開鍵は raw 非圧縮点 65B、秘密鍵は SEC1）
            var (publicKey, privateKey) = E2eeCrypto.GenerateEcdhKeyPair();
            try
            {
                // 公開鍵をサーバーに登録（raw 65B を Base64 で送信。WASM と同一形式）
                await CistaNasApiClientE2eeExtensions.SetMyPublicKeyAsync(_api, publicKey);

                // 秘密鍵を DPAPI (CurrentUser) で保護してローカルに永続化。
                // マウント時にパスワード入力不要で ECDH アンラップ可能。
                EcdhKeyStore.SavePrivateKey(Username!, privateKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(privateKey);
            }

            HasPublicKey = true;
            StatusMessage = "E2EE 鍵ペアを生成・登録しました。";
        }
        catch (Exception ex) { StatusMessage = $"鍵ペア生成失敗: {ex.Message}"; }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task CheckPublicKey()
    {
        if (_api is null) return;
        try
        {
            var pubKey = await CistaNasApiClientE2eeExtensions.GetPublicKeyAsync(_api, Username!);
            HasPublicKey = pubKey is not null;
        }
        catch { HasPublicKey = false; }
    }

    // ================================================================
    // 招待
    // ================================================================

    [RelayCommand]
    private async Task CreateInvitation()
    {
        if (_api is null || string.IsNullOrWhiteSpace(InviteTargetUsername)) return;
        try
        {
            var invitationId = await CistaNasApiClientInvitations.CreateInvitationAsync(_api, InviteTargetUsername.Trim());
            InvitationResult = $"招待 ID: {invitationId}";
            StatusMessage = "招待を作成しました。";
            InviteTargetUsername = "";
        }
        catch (Exception ex) { StatusMessage = $"招待作成失敗: {ex.Message}"; }
    }

    // ================================================================
    // タブ切替時のデータロード
    // ================================================================

    partial void OnSelectedTabIndexChanged(int value)
    {
        if (!IsLoggedIn || _api is null) return;
        _ = LoadTabDataAsync(value);
    }

    private async Task LoadTabDataAsync(int tabIndex)
    {
        try
        {
            switch (tabIndex)
            {
                case 0: await RefreshVolumesAsync(); break;
                case 1: await RefreshGroupsAsync(); break;
                case 2: await RefreshUsersAsync(); break;
                case 3:
                    await LoadEncryptionSettings();
                    await CheckPublicKey();
                    break;
            }
        }
        catch { }
    }
}

// ---- UI 用データクラス ----

public class GroupItem
{
    public required string GroupName { get; init; }
    public required string Owner { get; init; }
    public List<string> Members { get; set; } = [];
    public bool IsOwner(string username) => Owner == username;
}

public class UserItem
{
    public required string UserName { get; init; }
    public List<string> Roles { get; set; } = [];
    public string RoleText => Roles.FirstOrDefault() ?? "user";
}

public class InvitationItem
{
    public required string InvitationId { get; init; }
    public required string InviterUsername { get; init; }
    public required string TargetUsername { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
}

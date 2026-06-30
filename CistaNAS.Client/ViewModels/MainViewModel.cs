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
    [ObservableProperty] private int _encKdfIterations = 600_000;
    [ObservableProperty] private int _encSectorSize = 4096;

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

    private async Task CreateE2eeVolumeAsync()
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        using var kekBuf = new SecureBuffer(E2eeCrypto.DeriveKek(Username!, CreateVolPassword, salt, 600_000));
        byte[] masterKey = new byte[32];
        RandomNumberGenerator.Fill(masterKey);
        using var mkBuf = new SecureBuffer(masterKey);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(mkBuf.Buffer, kekBuf.Buffer);

        await _api!.CreateVolumeAsync(CreateVolName, Username!, nonce, ct, tag, salt, 600_000);
    }

    private async Task CreateGroupE2eeVolumeAsync()
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        using var kekBuf = new SecureBuffer(E2eeCrypto.DeriveKek(Username!, CreateVolPassword, salt, 600_000));
        byte[] masterKey = new byte[32];
        RandomNumberGenerator.Fill(masterKey);
        using var mkBuf = new SecureBuffer(masterKey);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(mkBuf.Buffer, kekBuf.Buffer);

        await CistaNasApiClientE2eeExtensions.CreateGroupVolumeAsync(_api!, CreateVolName, nonce, ct, tag, salt, 600_000);
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
            await CistaNasApiClientVolumes.RevokeAccessAsync(_api, SelectedVolume.Name, targetUser);
            StatusMessage = $"{targetUser} のアクセス権を剥奪しました。";
            await RefreshVolumesAsync();
            if (SelectedVolume is not null)
                AuthorizedUsers = new ObservableCollection<string>(SelectedVolume.AuthorizedUsers);
        }
        catch (Exception ex) { StatusMessage = $"アクセス権剥奪失敗: {ex.Message}"; }
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
            // 相手の公開鍵を取得
            string? recipientPubKeyB64 = await CistaNasApiClientE2eeExtensions.GetPublicKeyAsync(_api, EcdhUsername.Trim());
            if (recipientPubKeyB64 is null)
            {
                StatusMessage = "相手の公開鍵が登録されていません。";
                return;
            }

            // 自分の wrapped key を取得してアンラップ
            var wkInfo = await _api.GetWrappedKeyAsync(SelectedVolume.Name, Username!);
            using var kekBuf = new SecureBuffer(E2eeCrypto.DeriveKek(Username!, GrantGranterPassword, wkInfo.KdfSalt, wkInfo.KdfIterations));
            using var mkBuf = new SecureBuffer(E2eeCrypto.UnwrapMasterKey(wkInfo.WrappedNonce, wkInfo.WrappedCiphertext, wkInfo.WrappedTag, kekBuf.Buffer));

            // ECIES ラップ (E2eeCrypto を使用) - 相手公開鍵は raw 非圧縮点 65B
            byte[] recipientPubKeyRaw = Convert.FromBase64String(recipientPubKeyB64);
            var (ephPubKey, nonce, ct, tag) = E2eeCrypto.EcdhWrap(mkBuf.Buffer, recipientPubKeyRaw);

            await CistaNasApiClientE2eeExtensions.AddWrappedKeyAsync(_api, SelectedVolume.Name, EcdhUsername.Trim(), nonce, ct, tag, ephPubKey);
            StatusMessage = $"{EcdhUsername} に ECDH 共有しました。";
            EcdhUsername = "";
            GrantGranterPassword = "";
            await RefreshVolumesAsync();
        }
        catch (Exception ex) { StatusMessage = $"ECDH 共有失敗: {ex.Message}"; }
        finally { IsBusy = false; }
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
            EncKdfIterations = settings.KdfIterations;
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
                KdfIterations = EncKdfIterations,
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

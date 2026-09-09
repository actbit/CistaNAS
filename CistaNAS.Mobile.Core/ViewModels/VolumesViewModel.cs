using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CistaNAS.Client.Api;
using CistaNAS.Mobile.Core.Services;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Mobile.Core.ViewModels;

/// <summary>ボリューム一覧 + マウント (server / e2ee 両対応)。</summary>
public sealed partial class VolumesViewModel(AppServices app) : BusyViewModelBase
{
    public ObservableCollection<VolumeListItem> Volumes { get; } = [];

    [ObservableProperty]
    private bool _isMountPromptVisible;

    /// <summary>マウント対象として保留中のボリューム。</summary>
    private VolumeListItem? _pendingMount;

    [ObservableProperty]
    private string _mountPassword = "";

    public override string Title => "ボリューム";

    public bool HasVolumes => Volumes.Count > 0;

    public override async void OnNavigatedTo() => await RunBusyAsync(() => LoadCoreAsync(CancellationToken.None));

    [RelayCommand]
    private Task RefreshAsync(CancellationToken ct) => RunBusyAsync(() => LoadCoreAsync(ct));

    private async Task LoadCoreAsync(CancellationToken ct)
    {
        List<VolumeListItem> volumes = await app.Session.Api.ListVolumesAsync();
        Volumes.Clear();
        foreach (var v in volumes) Volumes.Add(v);
        OnPropertyChanged(nameof(HasVolumes));
    }

    /// <summary>ボリュームをタップ。必要ならパスワード入力を出してからファイル一覧へ遷移する。</summary>
    [RelayCommand]
    private void OpenVolume(VolumeListItem volume)
    {
        bool needsKey = IsE2ee(volume)
            ? !app.E2ee.HasKey(volume.Name)
            : !volume.IsMounted;
        if (needsKey)
        {
            _pendingMount = volume;
            MountPassword = "";
            IsMountPromptVisible = true;
            return;
        }
        app.Navigation.NavigateTo(new FileBrowserViewModel(app, volume));
    }

    [RelayCommand]
    private void CancelMount() => _pendingMount = null;

    [RelayCommand]
    private Task ConfirmMountAsync(CancellationToken ct) => RunBusyAsync(async () =>
    {
        var volume = _pendingMount;
        if (volume is null)
        {
            IsMountPromptVisible = false;
            return;
        }
        if (IsE2ee(volume))
            await MountE2eeAsync(volume, MountPassword, ct);
        else
            await MountServerAsync(volume, MountPassword, ct);
        IsMountPromptVisible = false;
        _pendingMount = null;
        app.Navigation.NavigateTo(new FileBrowserViewModel(app, volume));
    });

    private async Task MountServerAsync(VolumeListItem volume, string password, CancellationToken ct)
    {
        await app.Session.Api.MountVolumeAsync(volume.Name, password);
    }

    /// <summary>
    /// E2EE ボリュームのマウント: wrapped-key を取得してローカルでアンラップし、
    /// masterKey をセッションに登録する (サーバーに鍵は送らない)。
    /// 共有 v2 ボリューム (KeyEpoch ≥ 1) では全 epoch の GroupKey を自分の ECDH 秘密鍵で
    /// アンラップして v2 状態として登録する。オーナー (password wrap) のみ残置 v1 ファイルの
    /// 読み取り用に masterKey も復元する (v2 メンバーの wrapped-key は GroupKey wrap と同型のため
    /// masterKey としては扱わない)。
    /// サーバー側は作成時に自動マウント済みのことがあるため、未マウント時のみ解除を依頼する。
    /// </summary>
    private async Task MountE2eeAsync(VolumeListItem volume, string password, CancellationToken ct)
    {
        string username = app.Settings.Username ?? throw new InvalidOperationException("未ログインです。");

        // 共有 v2: 全 epoch の GroupKey wraps を取得してアンラップ
        var gki = await app.Session.Api.GetGroupKeyInfoAsync(volume.Name);
        if (gki is not null && gki.KeyEpoch >= 1)
        {
            byte[] privateKey = await app.EcdhKeys.GetOrCreatePrivateKeyAsync(app.Session.Api, username);
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
                        // 個別 epoch のアンラップ失敗は無視 (他の epoch で読めるファイルがある)
                    }
                }
                if (groupKeys.Count == 0)
                    throw new InvalidOperationException(
                        "共有 v2 の GroupKey を復号できませんでした（この共有から削除された可能性があります）。");
                app.E2ee.StoreV2State(volume.Name, gki.VolumeId, groupKeys);
            }
            finally
            {
                Array.Clear(privateKey);
            }

            // オーナー + password wrap の場合のみ masterKey も復元（残置 v1 ファイルの読み取り用）
            WrappedKeyInfo wk = await app.Session.Api.GetWrappedKeyAsync(volume.Name, username);
            bool passwordWrap = wk.WrapType is null || string.Equals(wk.WrapType, "password", StringComparison.Ordinal);
            if (passwordWrap && string.Equals(volume.OwnerUser, username, StringComparison.OrdinalIgnoreCase))
            {
                byte[] masterKey = app.E2ee.UnwrapMasterKey(username, password, wk, null);
                app.E2ee.StoreKey(volume.Name, masterKey, wk.ChunkSize);
            }

            if (!volume.IsMounted)
                await app.Session.Api.MountAsync(volume.Name);
            return;
        }

        // v1 パス (従来方式)
        WrappedKeyInfo wkV1 = await app.Session.Api.GetWrappedKeyAsync(volume.Name, username);

        byte[] masterKeyV1;
        if (string.Equals(wkV1.WrapType, "ecdh", StringComparison.Ordinal))
        {
            byte[] privateKey = await app.EcdhKeys.GetOrCreatePrivateKeyAsync(app.Session.Api, username);
            try
            {
                masterKeyV1 = app.E2ee.UnwrapMasterKey(username, null, wkV1, privateKey);
            }
            finally
            {
                Array.Clear(privateKey);
            }
        }
        else
        {
            masterKeyV1 = app.E2ee.UnwrapMasterKey(username, password, wkV1, null);
        }

        if (!volume.IsMounted)
            await app.Session.Api.MountAsync(volume.Name);
        app.E2ee.StoreKey(volume.Name, masterKeyV1, wkV1.ChunkSize);
    }

    [RelayCommand]
    private void CreateVolume() => app.Navigation.NavigateTo(new CreateVolumeViewModel(app));

    /// <summary>ログアウト: トークンと E2EE 鍵を破棄してログイン画面へ。</summary>
    [RelayCommand]
    private void Logout()
    {
        app.Session.ClearToken();
        app.E2ee.ClearKeys();
        app.Navigation.NavigateToRoot(new LoginViewModel(app));
    }

    private static bool IsE2ee(VolumeListItem v) =>
        string.Equals(v.EncryptionMode, "e2ee", StringComparison.OrdinalIgnoreCase)
        || string.Equals(v.EncryptionMode, "group-e2ee", StringComparison.OrdinalIgnoreCase);
}

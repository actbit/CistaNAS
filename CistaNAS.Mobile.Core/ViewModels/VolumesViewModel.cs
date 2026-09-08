using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CistaNAS.Client.Api;
using CistaNAS.Mobile.Core.Services;

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
    /// サーバー側は作成時に自動マウント済みのことがあるため、未マウント時のみ解除を依頼する。
    /// </summary>
    private async Task MountE2eeAsync(VolumeListItem volume, string password, CancellationToken ct)
    {
        string username = app.Settings.Username ?? throw new InvalidOperationException("未ログインです。");
        WrappedKeyInfo wk = await app.Session.Api.GetWrappedKeyAsync(volume.Name, username);

        byte[] masterKey;
        if (string.Equals(wk.WrapType, "ecdh", StringComparison.Ordinal))
        {
            byte[] privateKey = await app.EcdhKeys.GetOrCreatePrivateKeyAsync(app.Session.Api, username);
            try
            {
                masterKey = app.E2ee.UnwrapMasterKey(username, null, wk, privateKey);
            }
            finally
            {
                Array.Clear(privateKey);
            }
        }
        else
        {
            masterKey = app.E2ee.UnwrapMasterKey(username, password, wk, null);
        }

        if (!volume.IsMounted)
            await app.Session.Api.MountAsync(volume.Name);
        app.E2ee.StoreKey(volume.Name, masterKey, wk.ChunkSize);
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

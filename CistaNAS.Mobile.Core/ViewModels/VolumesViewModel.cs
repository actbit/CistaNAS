using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CistaNAS.Client.Api;
using CistaNAS.Mobile.Core.Services;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.Mobile.Core.ViewModels;

/// <summary>ボリューム一覧 + マウント (server / e2ee 両対応)。</summary>
public sealed partial class VolumesViewModel(AppServices app) : SessionViewModelBase
{
    public ObservableCollection<VolumeListItem> Volumes { get; } = [];

    [ObservableProperty]
    private bool _isMountPromptVisible;

    /// <summary>マウント対象として保留中のボリューム。</summary>
    private VolumeListItem? _pendingMount;

    [ObservableProperty]
    private string _mountPassword = "";

    /// <summary>E2EE Key Password（共有 v2 / ECDH 共有ボリュームの identity 鍵導出用。ボリュームパスワードとは別）。</summary>
    [ObservableProperty]
    private string _mountE2eePassword = "";

    /// <summary>保留中のマウントが E2EE ボリュームか（E2EE Key Password 入力欄の表示制御）。</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(MountExplanation))]
    private bool _isE2eeMount;

    public string MountExplanation => IsE2eeMount
        ? "このパスワードで端末内の鍵を復号します。パスワードはサーバーへ送信されません。"
        : "サーバー側でボリュームを解除するため、パスワードを接続先サーバーへ送信します。";

    public override string Title => "ボリューム";

    public bool HasVolumes => Volumes.Count > 0;

    /// <summary>旧バージョンが secure store に保存した ECDH 秘密鍵の残留警告。</summary>
    [ObservableProperty]
    private string? _legacyKeyWarning;

    public override async void OnNavigatedTo()
    {
        base.OnNavigatedTo();
        CheckLegacySecureStoreKey();
        await RunSessionBusyAsync(() => LoadCoreAsync(CancellationToken.None));
    }

    public override void OnNavigatedFrom()
    {
        base.OnNavigatedFrom();
        CancelMount();
        Volumes.Clear();
        OnPropertyChanged(nameof(HasVolumes));
    }

    /// <summary>旧方式の秘密鍵残留を検出したらユーザーに警告する（無言削除はしない）。</summary>
    private void CheckLegacySecureStoreKey()
    {
        string? username = app.Settings.Username;
        LegacyKeyWarning = username is not null
            && EcdhKeyManager.HasLegacySecureStoreKey(app.KeyStore, username)
                ? "旧バージョンが保存した ECDH 秘密鍵が端末に残留しています。新方式では秘密鍵を保存しないため削除できます。"
                : null;
    }

    /// <summary>旧 secure store の ECDH 秘密鍵を削除する（警告表示後の明示操作）。</summary>
    [RelayCommand]
    private void CleanupLegacyKey()
    {
        string? username = app.Settings.Username;
        if (username is null) return;
        EcdhKeyManager.DeleteLegacySecureStoreKey(app.KeyStore, username);
        CheckLegacySecureStoreKey();
    }

    [RelayCommand]
    private Task RefreshAsync(CancellationToken ct) => RunSessionBusyAsync(() => LoadCoreAsync(ct));

    private async Task LoadCoreAsync(CancellationToken ct)
    {
        using var operation = BeginOperation(app, ct);
        List<VolumeListItem> volumes = await app.Session.Api.ListVolumesAsync(operation.Cancellation);
        operation.Commit(() =>
        {
            Volumes.Clear();
            foreach (var v in volumes) Volumes.Add(v);
            OnPropertyChanged(nameof(HasVolumes));
        });
    }

    /// <summary>ボリュームをタップ。必要ならパスワード入力を出してからファイル一覧へ遷移する。</summary>
    [RelayCommand]
    private void OpenVolume(VolumeListItem volume)
    {
        CancelMount();
        bool needsKey = IsE2ee(volume)
            ? !app.E2ee.HasKey(volume.Name) && !app.E2ee.HasV2State(volume.Name)
            : !volume.IsMounted;
        if (needsKey)
        {
            _pendingMount = volume;
            MountPassword = "";
            MountE2eePassword = "";
            IsE2eeMount = IsE2ee(volume);
            IsMountPromptVisible = true;
            return;
        }
        app.Navigation.NavigateTo(new FileBrowserViewModel(app, volume));
    }

    [RelayCommand]
    private void CancelMount()
    {
        ConfirmMountCommand.Cancel();
        _pendingMount = null;
        IsMountPromptVisible = false;
        MountPassword = MountE2eePassword = "";
    }

    [RelayCommand]
    private Task ConfirmMountAsync(CancellationToken ct) => RunSessionBusyAsync(async () =>
    {
        var volume = _pendingMount;
        if (volume is null)
        {
            IsMountPromptVisible = false;
            return;
        }
        using var operation = BeginOperation(app, ct);
        string password = MountPassword, e2eePassword = MountE2eePassword;
        try
        {
            if (IsE2ee(volume)) await MountE2eeAsync(volume, password, e2eePassword, operation);
            else await MountServerAsync(volume, password, operation.Cancellation);
            operation.Commit(() =>
            {
                IsMountPromptVisible = false;
                _pendingMount = null;
                MountPassword = MountE2eePassword = "";
                app.Navigation.NavigateTo(new FileBrowserViewModel(app, volume));
            });
        }
        catch (OperationCanceledException)
        {
            if (ReferenceEquals(_pendingMount, volume)) CancelMount();
            throw;
        }
    });

    private async Task MountServerAsync(VolumeListItem volume, string password, CancellationToken ct)
    {
        await app.Session.Api.MountVolumeAsync(volume.Name, password, ct);
    }

    /// <summary>
    /// E2EE ボリュームのマウント: wrapped-key を取得してローカルでアンラップし、
    /// masterKey をセッションに登録する (サーバーに鍵は送らない)。
    /// 共有 v2 ボリューム (KeyEpoch ≥ 1) では全 epoch の GroupKey を E2EE Key Password から
    /// 決定論的に導出した ECDH identity 秘密鍵でアンラップして v2 状態として登録する
    /// （秘密鍵は RAM 上のみ。アンラップ後に破棄する）。オーナー (password wrap) のみ残置 v1
    /// ファイルの読み取り用に masterKey も復元する (v2 メンバーの wrapped-key は GroupKey wrap と
    /// 同型のため masterKey としては扱わない)。
    /// サーバー側は作成時に自動マウント済みのことがあるため、未マウント時のみ解除を依頼する。
    /// </summary>
    private async Task MountE2eeAsync(VolumeListItem volume, string password, string e2eePassword,
        ClientSessionOperation operation)
    {
        string username = app.Settings.Username ?? throw new InvalidOperationException("未ログインです。");

        // 共有 v2: 全 epoch の GroupKey wraps を取得してアンラップ
        var ct = operation.Cancellation;
        var gki = await app.Session.Api.GetGroupKeyInfoAsync(volume.Name, ct);
        operation.EnsureCurrent();
        if (gki is not null && gki.KeyEpoch >= 1)
        {
            WrappedKeyInfo wk = await app.Session.Api.GetWrappedKeyAsync(volume.Name, username, ct);
            operation.EnsureCurrent();
            byte[] privateKey = (await app.EcdhKeys.DeriveVerifiedAsync(app.Session.Api, username, e2eePassword)).PrivateKeySec1;
            var groupKeys = new Dictionary<int, byte[]>();
            byte[]? masterKey = null;
            try
            {
                operation.EnsureCurrent();
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
                // Do not publish a partial unlock if owner authentication or
                // the remote mount fails after group-key recovery.
                bool passwordWrap = wk.WrapType is null || string.Equals(wk.WrapType, "password", StringComparison.Ordinal);
                if (passwordWrap && string.Equals(volume.OwnerUser, username, StringComparison.OrdinalIgnoreCase))
                    masterKey = app.E2ee.UnwrapMasterKey(username, password, wk, null);
                if (!volume.IsMounted)
                    await app.Session.Api.MountAsync(volume.Name, ct);
                operation.Commit(() =>
                {
                    ct.ThrowIfCancellationRequested();
                    app.E2ee.StoreV2State(volume.Name, gki.VolumeId, groupKeys, wk.ChunkSize);
                    if (masterKey is not null) app.E2ee.StoreKey(volume.Name, masterKey, wk.ChunkSize);
                });
            }
            finally
            {
                if (masterKey is not null) Array.Clear(masterKey);
                foreach (byte[] groupKey in groupKeys.Values) Array.Clear(groupKey);
                Array.Clear(privateKey);
            }
            return;
        }

        // v1 パス (従来方式)
        WrappedKeyInfo wkV1 = await app.Session.Api.GetWrappedKeyAsync(volume.Name, username, ct);
        operation.EnsureCurrent();

        byte[] masterKeyV1;
        if (string.Equals(wkV1.WrapType, "ecdh", StringComparison.Ordinal))
        {
            // ECDH ラップキー: E2EE Key Password から決定論的に導出した identity 秘密鍵で
            // アンラップする（秘密鍵は RAM 上のみ。使用後すぐ破棄）。
            byte[] privateKey = (await app.EcdhKeys.DeriveVerifiedAsync(app.Session.Api, username, e2eePassword)).PrivateKeySec1;
            try
            {
                operation.EnsureCurrent();
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

        try
        {
            if (!volume.IsMounted)
                await app.Session.Api.MountAsync(volume.Name, ct);
            operation.Commit(() =>
            {
                ct.ThrowIfCancellationRequested();
                app.E2ee.StoreKey(volume.Name, masterKeyV1, wkV1.ChunkSize);
            });
        }
        finally { Array.Clear(masterKeyV1); }
    }

    [RelayCommand]
    private void CreateVolume() => app.Navigation.NavigateTo(new CreateVolumeViewModel(app));

    /// <summary>ログアウト: トークンと E2EE 鍵を破棄してログイン画面へ。</summary>
    [RelayCommand]
    private void Logout()
    {
        app.ClearSession();
        app.Navigation.NavigateToRoot(new LoginViewModel(app));
    }

    private static bool IsE2ee(VolumeListItem v) =>
        string.Equals(v.EncryptionMode, "e2ee", StringComparison.OrdinalIgnoreCase)
        || string.Equals(v.EncryptionMode, "group-e2ee", StringComparison.OrdinalIgnoreCase);
}

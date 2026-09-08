using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CistaNAS.Client.Api;
using CistaNAS.Mobile.Core.Services;

namespace CistaNAS.Mobile.Core.ViewModels;

/// <summary>一覧表示用のアイテム (server / e2ee 共通)。</summary>
public sealed class FileItem
{
    public required string Name { get; init; }
    public required string FullPath { get; init; }
    public required bool IsFolder { get; init; }
    public string Icon { get; init; } = FileCategoryService.FolderIcon;
    public string SizeText { get; init; } = "";
    public FileCategory Category { get; init; } = FileCategory.Other;
    public FileMetadata? ServerMeta { get; init; }
    public E2eeFileEntry? E2eeEntry { get; init; }
}

/// <summary>
/// ファイルブラウザ。
/// server モード: 全ファイル一覧から FileTreeBuilder でフォルダツリーを構築。
/// e2ee モード: フラットな一覧を masterKey で名前復号して表示 (サーバーにディレクトリ概念なし)。
/// </summary>
public sealed partial class FileBrowserViewModel(AppServices app, VolumeListItem volume) : BusyViewModelBase
{
    private List<FileMetadata>? _serverFiles;
    private List<(string Name, E2eeFileEntry Entry)>? _e2eeFiles;

    public ObservableCollection<FileItem> Items { get; } = [];

    [ObservableProperty]
    private string _currentPath = "";

    [ObservableProperty]
    private bool _canGoUp;

    public string VolumeName => volume.Name;

    public bool IsE2ee => IsE2eeVolume(volume);

    public string ModeBadge => IsE2ee ? "E2EE" : "サーバー暗号化";

    public override string Title => volume.Name;

    public override async void OnNavigatedTo() => await LoadAsync();

    [RelayCommand]
    private Task RefreshAsync(CancellationToken ct) => RunBusyAsync(LoadCoreAsync);

    private Task LoadAsync() => RunBusyAsync(LoadCoreAsync);

    private async Task LoadCoreAsync()
    {
        if (IsE2ee)
        {
            await LoadE2eeAsync();
        }
        else
        {
            // インスタンス側 ListFilesAsync (E2EE 用) と同名のため拡張メソッドを明示呼び出し
            _serverFiles = await CistaNasApiClientFiles.ListFilesAsync(app.Session.Api, volume.Name);
        }
        RefreshChildren();
    }

    /// <summary>E2EE: 一覧を取得して名前を復号する。復号できないエントリは (他ユーザーの鍵のため) スキップ表示。</summary>
    private async Task LoadE2eeAsync()
    {
        byte[] masterKey = app.E2ee.GetMasterKey(volume.Name);
        List<E2eeFileEntry> entries = await app.Session.Api.ListFilesAsync(volume.Name);
        _e2eeFiles = [];
        foreach (E2eeFileEntry e in entries)
        {
            string? name = E2eeFileTransferService.TryDecryptName(e.EncryptedName, masterKey);
            if (name is null) continue;
            _e2eeFiles.Add((name, e));
        }
        _e2eeFiles.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
    }

    private void RefreshChildren()
    {
        Items.Clear();
        if (IsE2ee)
        {
            foreach (var (name, entry) in _e2eeFiles ?? [])
            {
                var category = FileCategoryService.Categorize(name);
                Items.Add(new FileItem
                {
                    Name = name,
                    FullPath = name,
                    IsFolder = false,
                    Icon = FileCategoryService.GetIcon(category),
                    Category = category,
                    SizeText = FileCategoryService.FormatSize(E2eeFileTransferService.ComputePlainLength(entry)),
                    E2eeEntry = entry,
                });
            }
        }
        else
        {
            foreach (FileNode node in FileTreeBuilder.GetChildren(_serverFiles ?? [], CurrentPath))
            {
                Items.Add(new FileItem
                {
                    Name = node.Name,
                    FullPath = node.FullPath,
                    IsFolder = node.IsFolder,
                    Icon = node.IsFolder ? FileCategoryService.FolderIcon : FileCategoryService.GetIcon(node.Category),
                    Category = node.Category,
                    SizeText = node.IsFolder ? "" : FileCategoryService.FormatSize(node.Length),
                    ServerMeta = node.IsFolder ? null : new FileMetadata
                    {
                        Name = node.FullPath,
                        Length = node.Length,
                        ModifiedAt = node.ModifiedAt,
                    },
                });
            }
        }
        CanGoUp = !IsE2ee && FileTreeBuilder.GetParentPath(CurrentPath) is not null;
    }

    [RelayCommand]
    private void OpenItem(FileItem item)
    {
        if (item.IsFolder)
        {
            CurrentPath = item.FullPath;
            RefreshChildren();
            return;
        }

        switch (item.Category)
        {
            case FileCategory.Image:
                app.Navigation.NavigateTo(new ImageViewerViewModel(app, this, item));
                break;
            case FileCategory.Text:
                app.Navigation.NavigateTo(new TextViewerViewModel(app, this, item));
                break;
            default:
                // 動画・音声・その他は外部アプリに委譲
                app.Navigation.NavigateTo(new ExternalViewerViewModel(app, this, item));
                break;
        }
    }

    [RelayCommand]
    private void GoUp()
    {
        if (FileTreeBuilder.GetParentPath(CurrentPath) is not { } parent) return;
        CurrentPath = parent;
        RefreshChildren();
    }

    /// <summary>E2EE モードのボリュームからこの画面が出たとき、鍵をロックする。</summary>
    [RelayCommand]
    private void LockVolume()
    {
        app.E2ee.RemoveKey(volume.Name);
        if (app.Navigation.GoBack()) return;
        app.Navigation.NavigateToRoot(new VolumesViewModel(app));
    }

    private static bool IsE2eeVolume(VolumeListItem v) =>
        string.Equals(v.EncryptionMode, "e2ee", StringComparison.OrdinalIgnoreCase)
        || string.Equals(v.EncryptionMode, "group-e2ee", StringComparison.OrdinalIgnoreCase);
}

using System.Collections.ObjectModel;
using System.Net.Http;
using CistaNAS.Client.Api;
using CistaNAS.Client.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace CistaNAS.Client.ViewModels;

public partial class MainViewModel : ObservableObject
{
    // ログイン
    [ObservableProperty] private string _serverUrl = "https://localhost:5001";
    [ObservableProperty] private string _username = "";
    [ObservableProperty] private string _password = "";
    [ObservableProperty] private bool _isLoggedIn;
    [ObservableProperty] private string _statusMessage = "サーバーに接続してください。";
    [ObservableProperty] private bool _isBusy;

    // ボリューム一覧
    [ObservableProperty] private ObservableCollection<VolumeItem> _volumes = [];
    [ObservableProperty] private VolumeItem? _selectedVolume;

    // マウント
    [ObservableProperty] private string _selectedDriveLetter = "Z:";
    [ObservableProperty] private string _volumePassword = "";
    [ObservableProperty] private bool _showMountDialog;

    public ObservableCollection<string> AvailableDrives { get; } = [];

    private CistaNasApiClient? _api;
    private readonly MountService _mountService = new();

    public MainViewModel()
    {
        for (char c = 'D'; c <= 'Z'; c++)
            AvailableDrives.Add($"{c}:");
    }

    [RelayCommand]
    private async Task LoginAsync()
    {
        IsBusy = true;
        StatusMessage = "ログイン中...";
        try
        {
            var http = new HttpClient { BaseAddress = new Uri(ServerUrl.TrimEnd('/')) };
            http.Timeout = TimeSpan.FromSeconds(10);
            _api = new CistaNasApiClient(http);
            string token = await _api.LoginAsync(Username, Password);
            _api.SetToken(token);
            IsLoggedIn = true;
            StatusMessage = $"{Username} としてログインしました。";
            await RefreshVolumesAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"ログイン失敗: {ex.Message}";
        }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task RefreshVolumesAsync()
    {
        if (_api is null) return;
        try
        {
            var vols = await _api.ListVolumesAsync();
            Volumes = new ObservableCollection<VolumeItem>(
                vols.Select(v => new VolumeItem
                {
                    Name = v.Name,
                    EncryptionMode = v.EncryptionMode,
                    IsMounted = _mountService.IsMounted(v.Name),
                    MountPoint = _mountService.GetMountPoint(v.Name) ?? "",
                }));
        }
        catch (Exception ex)
        {
            StatusMessage = $"一覧取得失敗: {ex.Message}";
        }
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
            await _api.MountAsync(SelectedVolume.Name);
            await _mountService.MountAsync(SelectedVolume.Name, SelectedDriveLetter, _api, VolumePassword);
            StatusMessage = $"{SelectedVolume.Name} を {SelectedDriveLetter} にマウントしました。";
            ShowMountDialog = false;
            await RefreshVolumesAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"マウント失敗: {ex.Message}";
        }
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
            StatusMessage = $"{SelectedVolume.Name} をアンマウントしました。";
            await RefreshVolumesAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"アンマウント失敗: {ex.Message}";
        }
        finally { IsBusy = false; }
    }
}

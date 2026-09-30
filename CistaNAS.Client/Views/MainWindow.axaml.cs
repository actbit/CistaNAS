using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using CistaNAS.Client.ViewModels;
using CistaNAS.Client.Services;

namespace CistaNAS.Client.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    private void OpenViewer(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not MainViewModel vm || vm.SelectedVolume is not { IsMounted: true } volume) return;
        var viewer = new FilePreviewWindow
        {
            Title = $"CistaNAS Viewer — {volume.Name}",
            DataContext = new FilePreviewViewModel(new MountedFilePreviewService(volume.MountPoint))
        };
        void CloseViewer(string? name) { if (name is null || name == volume.Name) viewer.Close(); }
        void CloseWithOwner(object? _, EventArgs __) => viewer.Close();
        vm.ViewerClosing += CloseViewer;
        Closed += CloseWithOwner;
        viewer.Closed += (_, _) => { vm.ViewerClosing -= CloseViewer; Closed -= CloseWithOwner; };
        viewer.Show(this);
    }

    private void VolumeList_DoubleTapped(object? sender, TappedEventArgs e)
    {
        if (DataContext is MainViewModel vm && vm.SelectedVolume is not null)
        {
            if (vm.SelectedVolume.IsMounted)
                vm.UnmountCommand.Execute(null);
            else
                vm.ShowMountCommand.Execute(null);
        }
    }

    private void CloseMountDialog(object? sender, RoutedEventArgs e)
    {
        if (DataContext is MainViewModel vm)
            vm.ShowMountDialog = false;
    }

    private void CloseShareDialog(object? sender, RoutedEventArgs e)
    {
        if (DataContext is MainViewModel vm)
            vm.ShowShareDialog = false;
    }
}

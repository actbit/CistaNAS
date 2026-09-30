using Avalonia.Controls;
using Avalonia.Input;
using CistaNAS.Client.ViewModels;

namespace CistaNAS.Client.Views;

public partial class FilePreviewWindow : Window
{
    public FilePreviewWindow()
    {
        InitializeComponent();
        Opened += async (_, _) => { if (DataContext is FilePreviewViewModel vm) await vm.RefreshAsync(); };
        Closed += (_, _) => (DataContext as FilePreviewViewModel)?.Dispose();
    }
    private void OpenItem(object? sender, TappedEventArgs e) =>
        (DataContext as FilePreviewViewModel)?.OpenCommand.Execute(null);
}

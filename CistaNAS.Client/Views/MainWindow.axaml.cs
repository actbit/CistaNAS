using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using CistaNAS.Client.ViewModels;

namespace CistaNAS.Client.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
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
}

using Avalonia.Controls;
using Avalonia.Interactivity;
using CistaNAS.Mobile.Core.Services;
using CistaNAS.Mobile.Core.ViewModels;

namespace CistaNAS.Mobile.Views;

public partial class ShellView : UserControl
{
    public ShellView()
    {
        InitializeComponent();
        AttachedToVisualTree += (_, _) => HookBackRequested();
    }

    /// <summary>Android 戻るボタン (TopLevel.BackRequested) をナビゲーションに接続する。</summary>
    private void HookBackRequested()
    {
        var top = TopLevel.GetTopLevel(this);
        if (top is null) return;
        top.BackRequested += (_, e) =>
        {
            if (DataContext is ShellViewModel { Navigation.CanGoBack: true } shell)
            {
                shell.Navigation.GoBack();
                e.Handled = true;
            }
        };
    }
}

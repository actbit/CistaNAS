using CommunityToolkit.Mvvm.ComponentModel;
using CistaNAS.Mobile.Core.Services;

namespace CistaNAS.Mobile.Core.ViewModels;

/// <summary>ビジー状態とエラー表示を持つ ViewModel 基底。</summary>
public abstract partial class BusyViewModelBase : ViewModelBase
{
    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private string? _error;

    /// <summary>例外を UI 向けメッセージに変換する。必要に応じて派生で上書き。</summary>
    protected virtual string FriendlyError(Exception ex) => ex.Message;

    protected async Task RunBusyAsync(Func<Task> action)
    {
        if (IsBusy) return;
        Error = null;
        IsBusy = true;
        try
        {
            await action();
        }
        catch (Exception ex)
        {
            Error = FriendlyError(ex);
        }
        finally
        {
            IsBusy = false;
        }
    }
}

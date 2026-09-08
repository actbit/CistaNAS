using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace CistaNAS.Mobile.Core.Services;

/// <summary>画面 ViewModel の基底。ナビゲーションフックを持つ。</summary>
public abstract class ViewModelBase : ObservableObject
{
    /// <summary>ヘッダ表示用タイトル。</summary>
    public virtual string Title => GetType().Name.Replace("ViewModel", "");

    /// <summary>画面表示時に呼ばれる。</summary>
    public virtual void OnNavigatedTo() { }

    /// <summary>画面から離れるときに呼ばれる。</summary>
    public virtual void OnNavigatedFrom() { }

    /// <summary>Android 戻るボタンでこの画面が閉じられるか。</summary>
    public virtual bool CanGoBackFromHere => true;
}

/// <summary>
/// ViewModel スタック型ナビゲーション。View 側は Current の差し替えを表示する
/// (TransitioningContentControl + DataTemplate、DI コンテナ不使用)。
/// </summary>
public sealed partial class NavigationService : ObservableObject
{
    private readonly Stack<ViewModelBase> _stack = new();

    /// <summary>表示中の ViewModel。</summary>
    [ObservableProperty]
    private ViewModelBase? _current;

    /// <summary>戻れるか (Android 戻るボタンの消費判定に使用)。</summary>
    public bool CanGoBack => _stack.Count > 1;

    /// <summary>画面をスタックに積んで遷移する。</summary>
    public void NavigateTo(ViewModelBase vm)
    {
        Current?.OnNavigatedFrom();
        _stack.Push(vm);
        SetCurrent(vm);
    }

    /// <summary>スタックを空にして遷移する (ログイン後のルート画面等)。</summary>
    public void NavigateToRoot(ViewModelBase vm)
    {
        while (_stack.Count > 0)
        {
            ViewModelBase old = _stack.Pop();
            old.OnNavigatedFrom();
            if (old is IDisposable d) d.Dispose();
        }
        _stack.Push(vm);
        SetCurrent(vm);
    }

    /// <summary>1 つ戻る。戻れなければ false。</summary>
    public bool GoBack()
    {
        if (_stack.Count <= 1) return false;
        ViewModelBase popped = _stack.Pop();
        popped.OnNavigatedFrom();
        if (popped is IDisposable d) d.Dispose();
        SetCurrent(_stack.Peek());
        return true;
    }

    /// <summary>現在画面を残したままスタック中間の特定の画面へ戻る (未使用のフォールバック)。</summary>
    public void Reset() => _stack.Clear();

    private void SetCurrent(ViewModelBase vm)
    {
        Current = vm;
        vm.OnNavigatedTo();
        OnPropertyChanged(nameof(CanGoBack));
    }
}

using Avalonia.Controls;
using Avalonia.Controls.Templates;
using CistaNAS.Mobile.Core.Services;

namespace CistaNAS.Mobile;

/// <summary>
/// ViewModel の型名 (xxxViewModel) から Views 名前空間の xxxView を解決するテンプレート。
/// Core の ViewModels とヘッドの Views を対応させる。
/// </summary>
public sealed class ViewLocator : IDataTemplate
{
    public Control Build(object? param)
    {
        if (param is null) return new TextBlock();
        string viewName = "CistaNAS.Mobile.Views." + param.GetType().Name.Replace("ViewModel", "View", StringComparison.Ordinal);
        var viewType = Type.GetType(viewName) ?? typeof(ViewLocator).Assembly.GetType(viewName);
        if (viewType is not null)
            return (Control)Activator.CreateInstance(viewType)!;
        return new TextBlock { Text = "Not Found: " + viewName };
    }

    public bool Match(object? data) => data is ViewModelBase;
}

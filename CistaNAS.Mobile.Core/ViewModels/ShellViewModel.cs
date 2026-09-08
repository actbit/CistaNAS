using CommunityToolkit.Mvvm.Input;
using CistaNAS.Mobile.Core.Services;

namespace CistaNAS.Mobile.Core.ViewModels;

/// <summary>ルートシェル。Current ViewModel をホストし、ヘッダ / 戻るを提供する。</summary>
public sealed partial class ShellViewModel(NavigationService navigation) : ViewModelBase
{
    public NavigationService Navigation { get; } = navigation;

    public override string Title => "CistaNAS";

    [RelayCommand]
    private void GoBack() => Navigation.GoBack();
}

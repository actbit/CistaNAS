using CistaNAS.Web.Components.Auth;
using CistaNAS.Web.Services;

namespace CistaNAS.Web.Configuration;

/// <summary>
/// CistaNAS の Service 層 DI 登録。
/// 規約: ビジネスロジックは Service に集約。状態を持たない Service は Scoped、
/// マウント状態を保持する VolumeService のみ Singleton。
/// </summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddCistaNasServices(this IServiceCollection services)
    {
        // 認証（Task #3）
        services.AddSingleton<UserStore>();        // users.json：共有状態
        services.AddScoped<AuthService>();         // 状態なし

        // ボリューム（Task #4）
        services.AddSingleton<VolumeService>();    // Singleton: マウント状態保持

        // ファイル・ジャーナル（Task #5, #6）
        services.AddScoped<JournalService>();      // 状態なし
        services.AddScoped<FileService>();         // 状態なし

        // Blazor 認証状態
        services.AddScoped<AuthenticationStateService>();

        return services;
    }
}

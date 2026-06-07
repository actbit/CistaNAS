using CistaNAS.Wasm;
using CistaNAS.Wasm.Auth;
using CistaNAS.Wasm.Services;
using CistaNAS.Wasm.Services.HttpHandlers;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;

var builder = WebAssemblyHostBuilder.CreateDefault(args);

builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// API ベース URL: appsettings.json → 環境変数 → デフォルト
var apiBaseUrl = builder.Configuration["ApiBaseUrl"]
    ?? builder.HostEnvironment.BaseAddress;

// 認証状態管理
builder.Services.AddSingleton<WasmAuthStateProvider>();
builder.Services.AddSingleton<AuthenticationStateProvider>(sp => sp.GetRequiredService<WasmAuthStateProvider>());

// HttpClient (AuthHeaderHandler で JWT 自動付与)
builder.Services.AddSingleton<AuthHeaderHandler>();
builder.Services.AddHttpClient("api", client =>
{
    client.BaseAddress = new Uri(apiBaseUrl);
})
.AddHttpMessageHandler<AuthHeaderHandler>();

// 既定の HttpClient (API クライアントサービスで使用)
builder.Services.AddScoped(sp =>
{
    var httpClientFactory = sp.GetRequiredService<IHttpClientFactory>();
    return httpClientFactory.CreateClient("api");
});

// Service 登録
builder.Services.AddSingleton<ClientVolumeMountService>();
builder.Services.AddScoped<AuthApiClient>();
builder.Services.AddScoped<VolumeApiClient>();
builder.Services.AddScoped<FileApiClient>();
builder.Services.AddScoped<E2eeApiClient>();
builder.Services.AddScoped<AccountApiClient>();
builder.Services.AddScoped<GroupApiClient>();
builder.Services.AddScoped<EncryptionSettingsClient>();
builder.Services.AddScoped<E2eeInterop>();

var host = builder.Build();

// 起動時に sessionStorage からトークン復元
var authProvider = host.Services.GetRequiredService<WasmAuthStateProvider>();
await authProvider.TryRestoreAsync();

await host.RunAsync();

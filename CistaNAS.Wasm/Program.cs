using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using CistaNAS.Wasm;
using CistaNAS.Wasm.Auth;
using CistaNAS.Wasm.Services;
using CistaNAS.Wasm.Services.HttpHandlers;
using Microsoft.AspNetCore.Components;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// ---- 認証 ----
builder.Services.AddScoped<WasmAuthStateProvider>();
builder.Services.AddScoped<AuthenticationStateProvider>(sp => sp.GetRequiredService<WasmAuthStateProvider>());

// ---- HttpClient（AuthHeaderHandler で JWT 自動付与） ----
builder.Services.AddScoped<AuthHeaderHandler>();
builder.Services.AddScoped(sp =>
{
    var handler = sp.GetRequiredService<AuthHeaderHandler>();
    // WASM は同一サーバーでホストされるため相対 URL
    return new HttpClient(handler) { BaseAddress = new Uri(sp.GetRequiredService<NavigationManager>().BaseUri) };
});

// ---- API クライアントサービス ----
builder.Services.AddScoped<VolumeApiClient>();
builder.Services.AddScoped<FileApiClient>();
builder.Services.AddScoped<AuthApiClient>();
builder.Services.AddScoped<AccountApiClient>();
builder.Services.AddScoped<E2eeApiClient>();
builder.Services.AddScoped<GroupApiClient>();
builder.Services.AddScoped<EncryptionSettingsClient>();
builder.Services.AddScoped<ClientVolumeMountService>();
builder.Services.AddScoped<E2eeInterop>();

var host = builder.Build();

// 起動時に sessionStorage から JWT を復元
var auth = host.Services.GetRequiredService<WasmAuthStateProvider>();
await auth.TryRestoreAsync();

await host.RunAsync();

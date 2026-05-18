using System.Security.Cryptography;
using System.Text;
using CistaNAS.Web.Api;
using CistaNAS.Web.Components;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Services;
using CistaNAS.Web.WebDav;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Aspire 共通設定（テレメトリ・ヘルスチェック・サービスディスカバリ）
builder.AddServiceDefaults();

// ---- 設定 ----
builder.Services.AddOptions<CistaNasOptions>()
    .Bind(builder.Configuration.GetSection(CistaNasOptions.SectionName))
    .ValidateOnStart();
var cista = builder.Configuration.GetSection(CistaNasOptions.SectionName)
    .Get<CistaNasOptions>() ?? new CistaNasOptions();

// ---- JWT 認証 / 認可 ----
var signingKeyBytes = !string.IsNullOrWhiteSpace(cista.Jwt.SigningKey)
    ? Encoding.UTF8.GetBytes(cista.Jwt.SigningKey)
    : RandomNumberGenerator.GetBytes(48);

builder.Services.AddSingleton(new JwtSigningKey(signingKeyBytes));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = cista.Jwt.Issuer,
            ValidateAudience = true,
            ValidAudience = cista.Jwt.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(signingKeyBytes),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
        };
    })
    .AddScheme<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions, BasicAuthHandler>(
        "BasicAuth", null);

builder.Services.AddAuthorization(options =>
{
    // JWT と Basic Auth の両方を受け付けるポリシー
    options.AddPolicy("AnyAuth", policy =>
        policy.RequireAuthenticatedUser()
              .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme, "BasicAuth"));
});
builder.Services.AddCascadingAuthenticationState();

// ---- Service 層 DI 登録 ----
builder.Services.AddCistaNasServices();

// ---- WebDAV ----
builder.Services.AddScoped<WebDavHandler>();

// ---- E2EE ----
builder.Services.AddScoped<E2eeFileService>();

// ---- Blazor (Interactive Server rendering) ----
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    // 開発時のみ DetailedErrors（PROPFIND の 207 等のデバッグ用）
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

// ---- /api/v1 : REST API ----
var api = app.MapGroup("/api/v1");
app.MapCistaNasApi(api);

// ---- /dav : WebDAV ----
var dav = app.MapGroup("/dav/{volumeName}")
    .RequireAuthorization("AnyAuth");

dav.MapMethods("", ["OPTIONS"], (WebDavHandler h, HttpContext ctx) => h.OptionsAsync(ctx));
dav.MapMethods("{*path}", ["PROPFIND"],
    (string volumeName, string path, HttpContext ctx, WebDavHandler h) =>
        h.PropFindAsync(volumeName, path, ctx.Request.Headers["Depth"].FirstOrDefault(), ctx));
dav.MapGet("{*path}", (string volumeName, string path, HttpContext ctx, WebDavHandler h) =>
    h.Get(volumeName, path, ctx));
dav.MapMethods("{*path}", ["PUT"],
    (string volumeName, string path, HttpContext ctx, WebDavHandler h) =>
        h.Put(volumeName, path, ctx.Request));
dav.MapDelete("{*path}", (string volumeName, string path, HttpContext ctx, WebDavHandler h) =>
    h.Delete(volumeName, path, ctx));
dav.MapMethods("{*path}", ["MKCOL"],
    (string volumeName, string path, HttpContext ctx, WebDavHandler h) =>
        h.MkCol(volumeName, path, ctx));

app.MapDefaultEndpoints();

app.Run();

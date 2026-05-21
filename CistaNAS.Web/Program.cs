using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using CistaNAS.Web.Api;
using CistaNAS.Web.Components;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Identity;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using CistaNAS.Web.WebDav;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// ---- Kestrel リクエストサイズ制限 ----
builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.Limits.MaxRequestBodySize = 2L * 1024 * 1024 * 1024; // 2 GiB（NAS 用途）
    kestrel.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(30);
    kestrel.Limits.KeepAliveTimeout = TimeSpan.FromMinutes(2);
});

// Aspire 共通設定（テレメトリ・ヘルスチェック・サービスディスカバリ）
builder.AddServiceDefaults();

// ---- 設定 ----
builder.Services.AddOptions<CistaNasOptions>()
    .Bind(builder.Configuration.GetSection(CistaNasOptions.SectionName))
    .ValidateOnStart();
var cista = builder.Configuration.GetSection(CistaNasOptions.SectionName)
    .Get<CistaNasOptions>() ?? new CistaNasOptions();

// ---- JWT 認証 / 認可 ----
if (string.IsNullOrWhiteSpace(cista.Jwt.SigningKey))
{
    if (!builder.Environment.IsDevelopment())
        throw new InvalidOperationException("本番環境では CistaNas:Jwt:SigningKey の設定が必須です。");
    // 開発環境のみランダム生成を許可
}

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

// ---- レート制限 ----
builder.Services.AddRateLimiter(options =>
{
    // 認証エンドポイント: 1 IP あたり 10req/min
    options.AddPolicy("auth", httpContext =>
        RateLimitPartition.GetSlidingWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new SlidingWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(1),
                SegmentsPerWindow = 2,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0,
            }));
    // 一般 API: 1 IP あたり 100req/min
    options.AddPolicy("api", httpContext =>
        RateLimitPartition.GetSlidingWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new SlidingWindowRateLimiterOptions
            {
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(1),
                SegmentsPerWindow = 4,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0,
            }));
});

// ---- Service 層 DI 登録 ----
builder.Services.AddCistaNasServices();

// ---- WebDAV ----
builder.Services.AddScoped<WebDavHandler>();

// ---- E2EE ----
builder.Services.AddScoped<E2eeFileService>();
builder.Services.AddScoped<E2eeInterop>();

// ---- Blazor (Interactive Server rendering) ----
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// ---- CORS（外部クライアント向け） ----
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyHeader()
              .AllowAnyMethod()
              .SetIsOriginAllowed(origin =>
                  string.Equals(origin, "null", StringComparison.OrdinalIgnoreCase) || // Blazor SSR same-origin
                  true); // 制限する場合は特定ドメインに絞る
    });
});

var app = builder.Build();

// ---- DB 初期化 + データ移行 ----
using (var initScope = app.Services.CreateAsyncScope())
{
    var dbOpts = initScope.ServiceProvider.GetRequiredService<IOptions<CistaNasOptions>>().Value;
    var db = initScope.ServiceProvider.GetRequiredService<AppDbContext>();

    // SQLite の場合、DB ファイルの親ディレクトリが存在することを確認
    var dbPath = dbOpts.Database.ConnectionString
        ?? Path.Combine(dbOpts.DataRoot, "cista.db");
    Directory.CreateDirectory(Path.GetDirectoryName(dbPath) ?? dbOpts.DataRoot);

    await db.Database.EnsureCreatedAsync();

    // オブジェクトストレージ上の SQLite: 起動時にダウンロード
    var cloudSync = initScope.ServiceProvider.GetService<CloudSqliteSync>();
    if (cloudSync is not null)
    {
        await cloudSync.DownloadAsync();
        // ダウンロード後に再接続（EnsureCreated は空DBで実行済み）
        await db.Database.MigrateAsync();
    }

    // users.json / groups.json → DB 移行
    var storage = initScope.ServiceProvider.GetRequiredService<IStorageProvider>();
    var logger = initScope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("DataMigration");
    await DataMigrationService.MigrateIfNeededAsync(storage, db, logger);
}

// ---- シャットダウン時に CloudSqliteSync をアップロード ----
var lifetimeCloudSync = app.Services.GetService<CloudSqliteSync>();
if (lifetimeCloudSync is not null)
{
    var appLifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
    appLifetime.ApplicationStopping.Register(() =>
    {
        lifetimeCloudSync.UploadIfDirtyAsync().GetAwaiter().GetResult();
        lifetimeCloudSync.Dispose();
    });
}

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

// ---- セキュリティヘッダー ----
app.Use(async (ctx, next) =>
{
    var headers = ctx.Response.Headers;
    headers.XContentTypeOptions = "nosniff";
    headers.XFrameOptions = "SAMEORIGIN";
    headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
    if (!ctx.Request.Headers.ContainsKey("Content-Security-Policy"))
    {
        headers["Content-Security-Policy"] =
            "default-src 'self'; " +
            "script-src 'self'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data: blob:; " +
            "media-src 'self' blob:; " +
            "connect-src 'self'; " +
            "frame-ancestors 'self';";
    }
    await next();
});

app.UseCors();
app.UseRateLimiter();
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

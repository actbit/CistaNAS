using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using CistaNAS.Web.Api;
using CistaNAS.Web.Authorization;
using CistaNAS.Web.Components;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Identity;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using CistaNAS.Web.WebDav;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// ---- Kestrel リクエストサイズ制限 ----
builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.Limits.MaxRequestBodySize = 10L * 1024 * 1024 * 1024; // 10 GiB（NAS 用途）
    kestrel.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(30);
    kestrel.Limits.KeepAliveTimeout = TimeSpan.FromMinutes(2);
});

// Aspire 共通設定（テレメトリ・ヘルスチェック・サービスディスカバリ）
builder.AddServiceDefaults();

// ---- 設定 ----
builder.Services.AddOptions<CistaNasOptions>()
    .Bind(builder.Configuration.GetSection(CistaNasOptions.SectionName))
    .ValidateDataAnnotations()
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

if (signingKeyBytes.Length < 32)
    throw new InvalidOperationException("JWT 署名鍵は 32 バイト以上である必要があります。");

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
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
            ClockSkew = TimeSpan.FromSeconds(30),
        };
    })
    .AddScheme<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions, BasicAuthHandler>(
        "BasicAuth", null);

builder.Services.AddAuthorization(options =>
{
    // WebDAV: JWT と Basic Auth の両方を受け付けるポリシー
    options.AddPolicy("AnyAuth", policy =>
        policy.RequireAuthenticatedUser()
              .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme, "BasicAuth"));

    // ボリュームアクセス権 — ルートパラメータ "volumeName"（files / e2ee グループ）
    options.AddPolicy(CistaAuthorities.VolumeAccess, policy =>
        policy.RequireAuthenticatedUser()
              .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
              .AddRequirements(new CistaAuthorizationRequirement(CistaAuthorities.VolumeAccess, "volumeName")));

    // ボリュームアクセス権 — ルートパラメータ "name"（volumes グループ）
    options.AddPolicy("VolumeAccessByName", policy =>
        policy.RequireAuthenticatedUser()
              .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
              .AddRequirements(new CistaAuthorizationRequirement(CistaAuthorities.VolumeAccess, "name")));

    // ボリュームオーナー — ルートパラメータ "name"（E2EE の "volumeName" は ExtractVolumeName フォールバックで対応）
    options.AddPolicy(CistaAuthorities.VolumeOwner, policy =>
        policy.RequireAuthenticatedUser()
              .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
              .AddRequirements(new CistaAuthorizationRequirement(CistaAuthorities.VolumeOwner, "name")));

    // ボリュームオーナーまたは admin — ルートパラメータ "name"
    options.AddPolicy(CistaAuthorities.VolumeOwnerOrAdmin, policy =>
        policy.RequireAuthenticatedUser()
              .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
              .AddRequirements(new CistaAuthorizationRequirement(CistaAuthorities.VolumeOwnerOrAdmin, "name")));

    // admin ロール必須
    options.AddPolicy(CistaAuthorities.AdminOnly, policy =>
        policy.RequireAuthenticatedUser()
              .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
              .AddRequirements(new CistaAuthorizationRequirement(CistaAuthorities.AdminOnly)));
});

// 認可ハンドラ — VolumeService（Singleton）に依存するため Singleton 登録
builder.Services.AddSingleton<IAuthorizationHandler, CistaAuthorizationHandler>();
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
builder.Services.AddCistaNasServices(cista);

// ---- WebDAV ----
builder.Services.AddScoped<WebDavHandler>();

// ---- E2EE ----
builder.Services.AddScoped<E2eeInterop>();

// ---- Blazor (Interactive Server rendering) ----
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// ---- CORS（外部クライアント向け） ----
builder.Services.AddCors(options =>
{
    var allowedOrigins = cista.CorsAllowedOrigins;
    if (allowedOrigins.Count > 0)
    {
        options.AddDefaultPolicy(policy =>
        {
            policy.WithOrigins(allowedOrigins.ToArray())
                  .AllowAnyHeader()
                  .AllowAnyMethod();
        });
    }
});

var app = builder.Build();

if (string.IsNullOrWhiteSpace(cista.Jwt.SigningKey))
{
    var logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Startup");
    logger.LogWarning("JWT 署名鍵が未設定です。ランダム鍵を生成しました。再起動で全トークンが失効します。");
}

// ---- DB 初期化 + データ移行 ----
using (var initScope = app.Services.CreateAsyncScope())
{
    var dbOpts = initScope.ServiceProvider.GetRequiredService<IOptions<CistaNasOptions>>().Value;
    var db = initScope.ServiceProvider.GetRequiredService<AppDbContext>();

    // オブジェクトストレージ上の SQLite: 起動時にダウンロード（EnsureCreated の前）
    var cloudSync = initScope.ServiceProvider.GetService<CloudSqliteSync>();
    if (cloudSync is not null)
    {
        await cloudSync.DownloadAsync();
    }

    // SQLite の場合、DB ファイルの親ディレクトリが存在することを確認
    var dbPath = dbOpts.Database.ConnectionString
        ?? Path.Combine(dbOpts.DataRoot, "cista.db");
    Directory.CreateDirectory(Path.GetDirectoryName(dbPath) ?? dbOpts.DataRoot);

    await db.Database.EnsureCreatedAsync();

    // users.json / groups.json → DB 移行
    var storage = initScope.ServiceProvider.GetRequiredService<IStorageProvider>();
    var logger = initScope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("DataMigration");
    await DataMigrationService.MigrateIfNeededAsync(storage, db, logger);

    // 暗号化設定（VolumeOptions / AuthOptions）を DataRoot/cista-settings.json から読み込み
    // 旧: Pages/Settings.razor が appsettings.json を直接書き換えていた
    // 新: 専用ファイルで永続化、起動時に自動ロード (H-6)
    var settingsSvc = initScope.ServiceProvider.GetRequiredService<EncryptionSettingsService>();
    settingsSvc.LoadFromDiskIfExists();

    // ジャーナル復旧: 前回クラッシュで未コミットになったエントリを警告ログ出力
    var journalService = initScope.ServiceProvider.GetRequiredService<JournalService>();
    var journalLogger = initScope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("JournalRecovery");
    try
    {
        var metaStore = initScope.ServiceProvider.GetRequiredService<VolumeMetadataStore>();
        var volumeNames = await metaStore.ListVolumeNamesAsync();
        foreach (var volName in volumeNames)
        {
            if (await journalService.HasPendingAsync(volName))
            {
                var pending = await journalService.RecoverAsync(volName);
                journalLogger.LogWarning(
                    "ボリューム '{Volume}' に未コミットジャーナル {Count} 件を検出。前回クラッシュの可能性があります。",
                    volName, pending.Count);
                // 復旧は該当ボリュームの FileService 経路で再試行されるべきだが、
                // ここでは警告ログ出力のみ（破損データの上書きを防ぐため自動再構築はしない）
            }
        }
    }
    catch (Exception ex)
    {
        journalLogger.LogError(ex, "ジャーナル復旧に失敗しました。");
    }
}

// ---- CloudSqliteSync のシャットダウン処理は IHostedService.StopAsync で実行 ----
// （旧実装の .Wait() はデッドロックリスクがあったため IHostedService に移行）

if (app.Environment.IsDevelopment())
{
    // 開発時のみ DetailedErrors（PROPFIND の 207 等のデバッグ用）
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

// リバースプロキシ（nginx / Caddy / Traefik）背後で正しい IP とスキームを取得
// X-Forwarded-For / X-Forwarded-Proto ヘッダーを信用する
app.UseForwardedHeaders();

// Kestrel が HTTPS でリッスンしている場合のみリダイレクトを有効化
// （リバースプロキシで TLS 終端する構成では ASPNETCORE_URLS が http になるため無効化）
var urls = builder.Configuration["ASPNETCORE_URLS"] ?? "";
if (urls.Contains("https://", StringComparison.OrdinalIgnoreCase))
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

// ---- WASM SPA フォールバック ----
// API・WebDAVリクエスト以外を index.html にフォールバック
app.MapFallbackToFile("index.html");

// Server-side BlazorはWASM統合により無効化
// app.MapRazorComponents<App>()
//     .AddInteractiveServerRenderMode();

// ---- /api/v1 : REST API ----
var api = app.MapGroup("/api/v1");
app.MapCistaNasApi(api);

// ---- /dav : WebDAV ----
var dav = app.MapGroup("/dav/{volumeName}")
    .RequireAuthorization("AnyAuth")
    .RequireRateLimiting("auth");

dav.MapMethods("", ["OPTIONS"], (WebDavHandler h, HttpContext ctx) => h.OptionsAsync(ctx));
dav.MapMethods("{*path}", ["PROPFIND"],
    (string volumeName, string path, HttpContext ctx, WebDavHandler h) =>
        h.PropFindAsync(volumeName, path, ctx.Request.Headers["Depth"].FirstOrDefault(), ctx));
dav.MapGet("{*path}", async (string volumeName, string path, HttpContext ctx, WebDavHandler h) =>
    await h.Get(volumeName, path, ctx));
dav.MapMethods("{*path}", ["PUT"],
    (string volumeName, string path, HttpContext ctx, WebDavHandler h) =>
        h.Put(volumeName, path, ctx.Request));
dav.MapDelete("{*path}", (string volumeName, string path, HttpContext ctx, WebDavHandler h) =>
    h.Delete(volumeName, path, ctx));
dav.MapMethods("{*path}", ["MKCOL"],
    async (string volumeName, string path, HttpContext ctx, WebDavHandler h) =>
        await h.MkCol(volumeName, path, ctx));

app.MapDefaultEndpoints();

app.Run();

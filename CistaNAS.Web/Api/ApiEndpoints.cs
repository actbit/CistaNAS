using CistaNAS.Web.Models;
using CistaNAS.Web.Services;

namespace CistaNAS.Web.Api;

/// <summary>
/// /api/v1 ルート定義（rclone・RCX 等の外部クライアント向け）。
/// 各エンドポイントは Service へ委譲するのみで、ビジネスロジックを書かない。
/// </summary>
public static class ApiEndpoints
{
    public static IEndpointRouteBuilder MapCistaNasApi(this WebApplication app, IEndpointRouteBuilder api)
    {
        // ---- 認証 ----
        api.MapPost("/auth/login", (LoginRequest req, AuthService auth) =>
        {
            var res = auth.Authenticate(req.Username, req.Password);
            return res is null
                ? Results.Unauthorized()
                : Results.Ok(res);
        })
        .AllowAnonymous()
        .WithName("Login");

        // ---- ボリューム ----
        var volumes = api.MapGroup("/volumes")
            .RequireAuthorization();

        volumes.MapPost("/", (CreateVolumeRequest req, VolumeService vs) =>
        {
            try
            {
                var info = vs.Create(req.Name, req.Username, req.Password, req.Encrypted);
                return Results.Created($"/api/v1/volumes/{Uri.EscapeDataString(req.Name)}", info);
            }
            catch (VolumeException ex) { return Results.Conflict(new { error = ex.Message }); }
        })
        .WithName("CreateVolume");

        volumes.MapPost("/{name}/mount", (string name, MountRequest req, VolumeService vs) =>
        {
            try
            {
                return Results.Ok(vs.Mount(name, req.Username, req.Password));
            }
            catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .WithName("MountVolume");

        volumes.MapPost("/{name}/lock", (string name, VolumeService vs) =>
        {
            try
            {
                vs.Lock(name);
                return Results.NoContent();
            }
            catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .WithName("LockVolume");

        volumes.MapGet("/", (VolumeService vs) =>
            Results.Ok(vs.ListAll()))
        .WithName("ListVolumes");

        // ---- ファイル ----
        var files = api.MapGroup("/files/{volumeName}")
            .RequireAuthorization();

        files.MapGet("/", (string volumeName, FileService fs) =>
        {
            try
            {
                return Results.Ok(fs.List(volumeName));
            }
            catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .WithName("ListFiles");

        files.MapPost("/{*filePath}", async (string volumeName, string filePath, HttpContext ctx, FileService fs) =>
        {
            try
            {
                string fileName = Uri.UnescapeDataString(filePath.TrimStart('/'));
                long len = ctx.Request.ContentLength ?? 0;
                using var stream = ctx.Request.Body;
                var meta = await fs.UploadAsync(volumeName, fileName, stream, len, ctx.RequestAborted);
                return Results.Ok(meta);
            }
            catch (Exception ex) when (ex is VolumeException or FileServiceException)
            { return Results.BadRequest(new { error = ex.Message }); }
        })
        .WithName("UploadFile");

        files.MapGet("/{*filePath}", (string volumeName, string filePath, FileService fs) =>
        {
            try
            {
                string fileName = Uri.UnescapeDataString(filePath.TrimStart('/'));
                var dl = fs.Download(volumeName, fileName);
                return Results.Stream(dl.Stream, "application/octet-stream", dl.FileName,
                    enableRangeProcessing: false);
            }
            catch (FileServiceException ex) { return Results.NotFound(new { error = ex.Message }); }
            catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .WithName("DownloadFile")
        .AllowAnonymous(); // Blazor UI のダウンロード用（トークンをクエリパラメータで検証）

        files.MapDelete("/{*filePath}", (string volumeName, string filePath, FileService fs) =>
        {
            try
            {
                string fileName = Uri.UnescapeDataString(filePath.TrimStart('/'));
                fs.Delete(volumeName, fileName);
                return Results.NoContent();
            }
            catch (FileServiceException ex) { return Results.NotFound(new { error = ex.Message }); }
            catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .WithName("DeleteFile");

        return api;
    }
}

using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using Microsoft.AspNetCore.Http;

namespace CistaNAS.Web.WebDav;

/// <summary>
/// WebDAV プロトコルのハンドラ。
/// /dav/{volumeName}/ 以下のパスを処理し、FileService/VolumeService に委譲する。
/// </summary>
public sealed class WebDavHandler
{
    private readonly VolumeService _volumeService;
    private readonly FileService _fileService;

    public WebDavHandler(VolumeService volumeService, FileService fileService)
    {
        _volumeService = volumeService;
        _fileService = fileService;
    }

    private const string E2eeErrorMessage = "E2EE ボリュームは WebDAV 経由でのアクセスに対応していません。WebUI を使用してください。";

    private static string? GetUsername(HttpContext ctx) => ctx.User.Identity?.Name;

    private enum AccessResult { Ok, Forbidden, E2eeUnsupported }

    private async Task<AccessResult> CheckAccessAsync(string volumeName, HttpContext ctx)
    {
        if (!_volumeService.IsMounted(volumeName)) return AccessResult.Forbidden;
        try
        {
            var (_, header) = _volumeService.GetMounted(volumeName);
            if (header.IsE2ee) return AccessResult.E2eeUnsupported;
        }
        catch
        {
            return AccessResult.Forbidden;
        }
        string? username = GetUsername(ctx);
        if (username is null) return AccessResult.Forbidden;
        return await _volumeService.HasAccessAsync(volumeName, username)
            ? AccessResult.Ok
            : AccessResult.Forbidden;
    }

    // ---- OPTIONS ----

    public Task OptionsAsync(HttpContext ctx)
    {
        ctx.Response.Headers["DAV"] = "1";
        ctx.Response.Headers["Allow"] = "OPTIONS, PROPFIND, GET, HEAD, PUT, DELETE, MKCOL";
        ctx.Response.StatusCode = 200;
        return Task.CompletedTask;
    }

    // ---- PROPFIND ----

    public async Task PropFindAsync(string volumeName, string path, string? depthHeader, HttpContext ctx)
    {
        var access = await CheckAccessAsync(volumeName, ctx);
        if (access == AccessResult.E2eeUnsupported)
        {
            ctx.Response.StatusCode = 403;
            await ctx.Response.WriteAsJsonAsync(new { error = E2eeErrorMessage });
            return;
        }
        if (access != AccessResult.Ok)
        {
            ctx.Response.StatusCode = 403;
            await ctx.Response.WriteAsJsonAsync(new { error = $"ボリューム '{volumeName}' はマウントされていません。" });
            return;
        }

        int depth = WebDavXml.ParseDepth(depthHeader);
        var files = (await _fileService.ListAsync(volumeName)).Files;
        string prefix = NormalizePath(path);
        var resources = new List<WebDavResource>();

        bool isRoot = string.IsNullOrEmpty(prefix);

        if (depth == 0)
        {
            if (isRoot || files.Any(f => f.Name.StartsWith(prefix + "/", StringComparison.Ordinal)))
            {
                resources.Add(new WebDavResource
                {
                    Path = prefix,
                    IsCollection = true,
                    LastModified = DateTimeOffset.UtcNow,
                });
            }
            else
            {
                var file = files.FirstOrDefault(f => f.Name == prefix);
                if (file is not null)
                {
                    resources.Add(new WebDavResource
                    {
                        Path = file.Name,
                        IsCollection = false,
                        Size = file.Length,
                        LastModified = file.ModifiedAt,
                    });
                }
                else
                {
                    ctx.Response.StatusCode = 404;
                    return;
                }
            }
        }
        else
        {
            resources.Add(new WebDavResource
            {
                Path = prefix,
                IsCollection = true,
                LastModified = DateTimeOffset.UtcNow,
            });

            foreach (var child in GetDirectChildren(files, prefix))
                resources.Add(child);
        }

        string baseUrl = $"/dav/{Uri.EscapeDataString(volumeName)}";
        string xml = WebDavXml.BuildMultiStatus(resources, baseUrl);
        ctx.Response.StatusCode = 207; // Multi-Status
        ctx.Response.ContentType = "application/xml; charset=utf-8";
        await ctx.Response.WriteAsync(xml);
    }

    // ---- GET ----

    public async Task<IResult> Get(string volumeName, string path, HttpContext ctx)
    {
        var access = await CheckAccessAsync(volumeName, ctx);
        if (access == AccessResult.E2eeUnsupported)
            return Results.BadRequest(new { error = E2eeErrorMessage });
        if (access != AccessResult.Ok)
            return Results.Forbid();

        string name = NormalizePath(path);
        if (string.IsNullOrEmpty(name))
            return Results.Ok("CistaNAS WebDAV");

        try
        {
            var dl = await _fileService.DownloadAsync(volumeName, name, ctx.RequestAborted);
            return Results.Stream(dl.Stream, "application/octet-stream", dl.FileName);
        }
        catch (FileServiceException)
        {
            return Results.NotFound();
        }
    }

    // ---- PUT ----

    public async Task<IResult> Put(string volumeName, string path, HttpRequest request)
    {
        var access = await CheckAccessAsync(volumeName, request.HttpContext);
        if (access == AccessResult.E2eeUnsupported)
            return Results.BadRequest(new { error = E2eeErrorMessage });
        if (access != AccessResult.Ok)
            return Results.Forbid();

        string name = NormalizePath(path);
        if (string.IsNullOrEmpty(name))
            return Results.BadRequest(new { error = "ファイル名が必要です。" });

        long len = request.ContentLength ?? 0;
        try
        {
            await _fileService.UploadAsync(volumeName, name, request.Body, len, request.HttpContext.RequestAborted);
            return Results.Created();
        }
        catch (VolumeException) { return Results.BadRequest(); }
        catch (FileServiceException) { return Results.BadRequest(); }
    }

    // ---- DELETE ----

    public async Task<IResult> Delete(string volumeName, string path, HttpContext ctx)
    {
        var access = await CheckAccessAsync(volumeName, ctx);
        if (access == AccessResult.E2eeUnsupported)
            return Results.BadRequest(new { error = E2eeErrorMessage });
        if (access != AccessResult.Ok)
            return Results.Forbid();

        string name = NormalizePath(path);
        if (string.IsNullOrEmpty(name))
            return Results.BadRequest(new { error = "ファイル名が必要です。" });

        try
        {
            await _fileService.DeleteAsync(volumeName, name);
            return Results.NoContent();
        }
        catch (FileServiceException)
        {
            return Results.NotFound();
        }
    }

    // ---- MKCOL ----

    public async Task<IResult> MkCol(string volumeName, string path, HttpContext ctx)
    {
        var access = await CheckAccessAsync(volumeName, ctx);
        if (access == AccessResult.E2eeUnsupported)
            return Results.BadRequest(new { error = E2eeErrorMessage });
        if (access != AccessResult.Ok)
            return Results.Forbid();

        // MKCOL は何もしない（ディレクトリ構造を持たないため）
        return Results.Created();
    }

    // ---- ヘルパー ----

    private static string NormalizePath(string? path)
    {
        if (string.IsNullOrEmpty(path)) return "";
        string decoded;
        try
        {
            decoded = Uri.UnescapeDataString(path.Trim('/'));
        }
        catch
        {
            throw new FileServiceException("ファイルパスに不正なエンコーディングが含まれています。");
        }
        string normalized = decoded.Replace('\\', '/');

        var parts = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var safeParts = new List<string>(parts.Length);
        foreach (var part in parts)
        {
            if (part == ".." || part == ".") continue;
            if (part.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
                throw new FileServiceException("ファイル名に使用できない文字が含まれています。");
            safeParts.Add(part);
        }
        string safe = string.Join('/', safeParts);
        if (string.IsNullOrEmpty(safe))
            throw new FileServiceException("ファイル名が無効です。");
        return safe;
    }

    private static List<WebDavResource> GetDirectChildren(
        IReadOnlyList<FileMetadata> files, string prefix)
    {
        var result = new List<WebDavResource>();
        var seenDirs = new HashSet<string>(StringComparer.Ordinal);

        foreach (var f in files)
        {
            string rest;
            if (string.IsNullOrEmpty(prefix))
            {
                rest = f.Name;
            }
            else if (f.Name.StartsWith(prefix + "/", StringComparison.Ordinal))
            {
                rest = f.Name[(prefix.Length + 1)..];
            }
            else
            {
                continue;
            }

            int slash = rest.IndexOf('/');
            if (slash < 0)
            {
                result.Add(new WebDavResource
                {
                    Path = f.Name,
                    IsCollection = false,
                    Size = f.Length,
                    LastModified = f.ModifiedAt,
                });
            }
            else
            {
                string dir = prefix.Length == 0 ? rest[..slash] : $"{prefix}/{rest[..slash]}";
                if (seenDirs.Add(dir))
                {
                    result.Add(new WebDavResource
                    {
                        Path = dir,
                        IsCollection = true,
                        LastModified = f.ModifiedAt,
                    });
                }
            }
        }
        return result;
    }

}

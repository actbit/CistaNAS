using System.Text;
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
    private readonly E2eeFileService _e2eeFileService;

    public WebDavHandler(VolumeService volumeService, FileService fileService, E2eeFileService e2eeFileService)
    {
        _volumeService = volumeService;
        _fileService = fileService;
        _e2eeFileService = e2eeFileService;
    }

    private static string? GetUsername(HttpContext ctx) => ctx.User.Identity?.Name;

    private bool CheckAccess(string volumeName, HttpContext ctx)
    {
        if (!_volumeService.IsMounted(volumeName)) return false;
        string? username = GetUsername(ctx);
        if (username is null) return false;
        return _volumeService.HasAccess(volumeName, username);
    }

    private bool IsE2ee(string volumeName)
    {
        try
        {
            var (_, header) = _volumeService.GetMounted(volumeName);
            return header.IsE2ee;
        }
        catch { return false; }
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

    public Task PropFindAsync(string volumeName, string path, string? depthHeader, HttpContext ctx)
    {
        if (!CheckAccess(volumeName, ctx))
        {
            ctx.Response.StatusCode = 403;
            return ctx.Response.WriteAsJsonAsync(new { error = $"ボリューム '{volumeName}' はマウントされていません。" });
        }
        // E2EE ボリュームの場合は opaque なファイル一覧を返す
        if (IsE2ee(volumeName))
            return PropFindE2ee(volumeName, path, ctx);

        int depth = WebDavXml.ParseDepth(depthHeader);
        var files = _fileService.List(volumeName).Files;
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
                    return Task.CompletedTask;
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
        return ctx.Response.WriteAsync(xml);
    }

    // ---- GET ----

    public IResult Get(string volumeName, string path, HttpContext ctx)
    {
        if (!CheckAccess(volumeName, ctx))
            return Results.Forbid();

        string name = NormalizePath(path);
        if (string.IsNullOrEmpty(name))
            return Results.Ok("CistaNAS WebDAV");

        try
        {
            var dl = _fileService.Download(volumeName, name);
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
        if (!CheckAccess(volumeName, request.HttpContext))
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

    public IResult Delete(string volumeName, string path, HttpContext ctx)
    {
        if (!CheckAccess(volumeName, ctx))
            return Results.Forbid();

        string name = NormalizePath(path);
        if (string.IsNullOrEmpty(name))
            return Results.BadRequest(new { error = "ファイル名が必要です。" });

        try
        {
            _fileService.Delete(volumeName, name);
            return Results.NoContent();
        }
        catch (FileServiceException)
        {
            return Results.NotFound();
        }
    }

    // ---- MKCOL ----

    public IResult MkCol(string volumeName, string path, HttpContext ctx)
    {
        if (!CheckAccess(volumeName, ctx))
            return Results.Forbid();

        return Results.Created();
    }

    // ---- ヘルパー ----

    private static string NormalizePath(string? path)
    {
        if (string.IsNullOrEmpty(path)) return "";
        string decoded = Uri.UnescapeDataString(path.Trim('/'));
        string normalized = decoded.Replace('\\', '/');

        var parts = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var safeParts = new List<string>(parts.Length);
        foreach (var part in parts)
        {
            if (part == ".." || part == ".") continue;
            if (part.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) continue;
            safeParts.Add(part);
        }
        return string.Join('/', safeParts);
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

    // ---- E2EE 対応 ----

    private Task PropFindE2ee(string volumeName, string path, HttpContext ctx)
    {
        var e2eeFiles = _e2eeFileService.ListFiles(volumeName).Files;
        var resources = new List<WebDavResource>();

        resources.Add(new WebDavResource
        {
            Path = NormalizePath(path),
            IsCollection = true,
            LastModified = DateTimeOffset.UtcNow,
        });

        foreach (var f in e2eeFiles)
        {
            resources.Add(new WebDavResource
            {
                Path = f.EncryptedName,
                IsCollection = false,
                Size = f.EncryptedLength,
                LastModified = f.ModifiedAt,
            });
        }

        string baseUrl = $"/dav/{Uri.EscapeDataString(volumeName)}";
        string xml = WebDavXml.BuildMultiStatus(resources, baseUrl);
        ctx.Response.StatusCode = 207;
        ctx.Response.ContentType = "application/xml; charset=utf-8";
        return ctx.Response.WriteAsync(xml);
    }
}

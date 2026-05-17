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

    public WebDavHandler(VolumeService volumeService, FileService fileService)
    {
        _volumeService = volumeService;
        _fileService = fileService;
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
        if (!_volumeService.IsMounted(volumeName))
        {
            ctx.Response.StatusCode = 400;
            return ctx.Response.WriteAsJsonAsync(new { error = $"ボリューム '{volumeName}' はマウントされていません。" });
        }

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

    public IResult Get(string volumeName, string path)
    {
        if (!_volumeService.IsMounted(volumeName))
            return Results.BadRequest(new { error = $"ボリューム '{volumeName}' はマウントされていません。" });

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
        if (!_volumeService.IsMounted(volumeName))
            return Results.BadRequest(new { error = $"ボリューム '{volumeName}' はマウントされていません。" });

        string name = NormalizePath(path);
        if (string.IsNullOrEmpty(name))
            return Results.BadRequest(new { error = "ファイル名が必要です。" });

        long len = request.ContentLength ?? 0;
        try
        {
            await _fileService.UploadAsync(volumeName, name, request.Body, len, request.HttpContext.RequestAborted);
            return Results.Created();
        }
        catch (Exception ex) when (ex is VolumeException or FileServiceException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    // ---- DELETE ----

    public IResult Delete(string volumeName, string path)
    {
        if (!_volumeService.IsMounted(volumeName))
            return Results.BadRequest(new { error = $"ボリューム '{volumeName}' はマウントされていません。" });

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

    public IResult MkCol(string volumeName, string path)
    {
        if (!_volumeService.IsMounted(volumeName))
            return Results.BadRequest(new { error = $"ボリューム '{volumeName}' はマウントされていません。" });

        return Results.Created();
    }

    // ---- ヘルパー ----

    private static string NormalizePath(string? path)
    {
        if (string.IsNullOrEmpty(path)) return "";
        return path.Trim('/').Replace("%20", " ");
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

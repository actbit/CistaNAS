using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using CistaNAS.Web.Volume;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace CistaNAS.Web.Api;

/// <summary>E2EE ボリューム向け API エンドポイント（/api/v1/e2ee）。</summary>
public static class E2eeEndpoints
{
    public static IEndpointRouteBuilder MapE2eeApi(this IEndpointRouteBuilder group)
    {
        var e2ee = group.MapGroup("/e2ee").RequireAuthorization();

        e2ee.MapPost("/create-volume", CreateVolume);
        e2ee.MapPost("/{volumeName}/mount", Mount);
        e2ee.MapPost("/{volumeName}/create-file", CreateFile);
        e2ee.MapPost("/{volumeName}/upload-chunk/{fileId}/{chunkIndex}", UploadChunk);
        e2ee.MapGet("/{volumeName}/download-chunk/{fileId}/{chunkIndex}", DownloadChunk);
        e2ee.MapPatch("/{volumeName}/finalize-file/{fileId}", FinalizeFile);
        e2ee.MapDelete("/{volumeName}/files/{fileId}", DeleteFile);
        e2ee.MapGet("/{volumeName}/files", ListFiles);
        e2ee.MapPost("/{volumeName}/add-wrapped-key", AddWrappedKey);

        return e2ee;
    }

    private static IResult CreateVolume(E2eeCreateVolumeRequest req, VolumeService volumeService, HttpContext ctx)
    {
        string username = ctx.User.Identity?.Name ?? "";
        if (string.IsNullOrEmpty(username))
            return Results.Unauthorized();

        try
        {
            var info = volumeService.CreateE2ee(req.VolumeName, req.Username, req.WrappedMasterKey, req.ChunkSize);
            return Results.Created($"/api/v1/e2ee/{req.VolumeName}/mount", info);
        }
        catch (VolumeException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private static IResult Mount(string volumeName, VolumeService volumeService, HttpContext ctx)
    {
        string username = ctx.User.Identity?.Name ?? "";
        if (string.IsNullOrEmpty(username))
            return Results.Unauthorized();

        try
        {
            var info = volumeService.MountE2ee(volumeName, username);
            return Results.Ok(info);
        }
        catch (VolumeException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private static IResult CreateFile(string volumeName, E2eeCreateFileRequest req, E2eeFileService e2eeFs)
    {
        try
        {
            var entry = e2eeFs.CreateFile(volumeName, req);
            return Results.Created($"/api/v1/e2ee/{volumeName}/upload-chunk/{entry.FileId}/0", entry);
        }
        catch (FileServiceException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private static async Task<IResult> UploadChunk(string volumeName, string fileId, int chunkIndex,
        HttpRequest request, E2eeFileService e2eeFs)
    {
        long len = request.ContentLength ?? 0;
        try
        {
            await e2eeFs.UploadChunkAsync(volumeName, fileId, chunkIndex, request.Body, len, request.HttpContext.RequestAborted);
            return Results.Ok();
        }
        catch (FileServiceException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private static IResult DownloadChunk(string volumeName, string fileId, int chunkIndex, E2eeFileService e2eeFs)
    {
        try
        {
            var (stream, length) = e2eeFs.DownloadChunk(volumeName, fileId, chunkIndex);
            return Results.Stream(stream, "application/octet-stream");
        }
        catch (FileServiceException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private static IResult FinalizeFile(string volumeName, string fileId, E2eeFinalizeFileRequest req, E2eeFileService e2eeFs)
    {
        try
        {
            e2eeFs.FinalizeFile(volumeName, fileId, req);
            return Results.Ok();
        }
        catch (FileServiceException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private static IResult DeleteFile(string volumeName, string fileId, E2eeFileService e2eeFs)
    {
        try
        {
            e2eeFs.DeleteFile(volumeName, fileId);
            return Results.NoContent();
        }
        catch (FileServiceException ex)
        {
            return Results.NotFound(new { error = ex.Message });
        }
    }

    private static IResult ListFiles(string volumeName, E2eeFileService e2eeFs)
    {
        try
        {
            return Results.Ok(e2eeFs.ListFiles(volumeName));
        }
        catch (FileServiceException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private static IResult AddWrappedKey(string volumeName, E2eeAddWrappedKeyRequest req,
        VolumeService volumeService, HttpContext ctx)
    {
        string granter = ctx.User.Identity?.Name ?? "";
        if (string.IsNullOrEmpty(granter))
            return Results.Unauthorized();

        try
        {
            volumeService.AddE2eeWrappedKey(volumeName, granter, req.Username, req.WrappedMasterKey);
            return Results.Ok();
        }
        catch (VolumeException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }
}

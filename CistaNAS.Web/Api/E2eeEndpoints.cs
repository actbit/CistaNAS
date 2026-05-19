using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using CistaNAS.Web.Volume;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

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

        // ---- ECDH public key management ----
        e2ee.MapGet("/public-key/{username}", GetPublicKey);
        e2ee.MapPut("/my-public-key", SetMyPublicKey);

        // ---- Group E2EE volume ----
        e2ee.MapPost("/create-group-volume", CreateGroupVolume);
        e2ee.MapGet("/{volumeName}/group-members", GetGroupMembers);
        e2ee.MapPost("/{volumeName}/add-wrapped-keys-batch", AddWrappedKeysBatch);

        // ---- Invitation ----
        e2ee.MapPost("/invitations", CreateInvitation);
        e2ee.MapGet("/invitations/{invitationId}", GetInvitation);
        e2ee.MapPost("/invitations/{invitationId}/accept", AcceptInvitation);

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

    // ---- ECDH public key ----

    private static IResult GetPublicKey(string username, UserStore userStore)
    {
        var pubKey = userStore.GetPublicKey(username);
        return pubKey is not null
            ? Results.Ok(new { publicKey = pubKey })
            : Results.NotFound(new { error = "公開鍵が登録されていません。" });
    }

    private static IResult SetMyPublicKey(SetPublicKeyRequest req, HttpContext ctx, UserStore userStore)
    {
        string username = ctx.User.Identity?.Name ?? "";
        if (string.IsNullOrEmpty(username)) return Results.Unauthorized();
        try
        {
            userStore.UpdatePublicKey(username, req.PublicKey);
            return Results.Ok();
        }
        catch (Exception ex) { return Results.BadRequest(new { error = ex.Message }); }
    }

    // ---- Group E2EE volume ----

    private static IResult CreateGroupVolume(CreateGroupE2eeVolumeRequest req,
        VolumeService vs, HttpContext ctx)
    {
        string username = ctx.User.Identity?.Name ?? "";
        if (string.IsNullOrEmpty(username)) return Results.Unauthorized();
        try
        {
            var info = vs.CreateGroupE2ee(req.GroupName, username, req.OwnerWrappedKey, req.ChunkSize);
            return Results.Created($"/api/v1/e2ee/{info.Name}/mount", info);
        }
        catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
    }

    private static IResult GetGroupMembers(string volumeName, VolumeService vs, HttpContext ctx)
    {
        string username = ctx.User.Identity?.Name ?? "";
        if (string.IsNullOrEmpty(username)) return Results.Unauthorized();
        try
        {
            var members = vs.GetGroupMembersWithPublicKeys(volumeName, username);
            return Results.Ok(members.Select(m => new { m.Username, m.PublicKey }));
        }
        catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
    }

    private static IResult AddWrappedKeysBatch(string volumeName, AddE2eeWrappedKeysBatchRequest req,
        VolumeService vs, HttpContext ctx)
    {
        string username = ctx.User.Identity?.Name ?? "";
        if (string.IsNullOrEmpty(username)) return Results.Unauthorized();
        try
        {
            vs.AddE2eeWrappedKeysBatch(volumeName, username, req.WrappedKeys);
            return Results.Ok();
        }
        catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
    }

    // ---- Invitation ----

    private static IResult CreateInvitation(CreateInvitationRequest req, HttpContext ctx,
        InvitationService invSvc)
    {
        string username = ctx.User.Identity?.Name ?? "";
        if (string.IsNullOrEmpty(username)) return Results.Unauthorized();
        var record = invSvc.Create(username, req.TargetUsername);
        return Results.Ok(new { record.InvitationId });
    }

    private static IResult GetInvitation(string invitationId, InvitationService invSvc)
    {
        var record = invSvc.Find(invitationId);
        return record is null
            ? Results.NotFound(new { error = "招待が見つかりません。" })
            : Results.Ok(new { record.InvitationId, record.InviterUsername, record.CreatedAt });
    }

    private static IResult AcceptInvitation(string invitationId, AcceptInvitationRequest req,
        InvitationService invSvc)
    {
        var record = invSvc.Find(invitationId);
        if (record is null) return Results.NotFound(new { error = "招待が見つかりません。" });
        try
        {
            invSvc.SetAcceptedData(invitationId, req.EncryptedPublicKey, req.Nonce);
            return Results.Ok();
        }
        catch (Exception ex) { return Results.BadRequest(new { error = ex.Message }); }
    }
}

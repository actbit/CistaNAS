using CistaNAS.Web.Authorization;
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
        var e2ee = group.MapGroup("/e2ee").RequireAuthorization().RequireRateLimiting("api");

        // ---- ボリューム操作（VolumeAccess ポリシー） ----
        e2ee.MapPost("/create-volume", CreateVolume);
        e2ee.MapPost("/{volumeName}/mount", Mount)
            .RequireAuthorization(CistaAuthorities.VolumeAccess);
        e2ee.MapGet("/{volumeName}/wrapped-key/{username}", GetWrappedKey)
            .RequireAuthorization(CistaAuthorities.VolumeAccess);
        e2ee.MapPost("/{volumeName}/create-file", CreateFile)
            .RequireAuthorization(CistaAuthorities.VolumeAccess);
        e2ee.MapPost("/{volumeName}/upload-chunk/{fileId}/{chunkIndex}", UploadChunk)
            .RequireAuthorization(CistaAuthorities.VolumeAccess);
        e2ee.MapGet("/{volumeName}/download-chunk/{fileId}/{chunkIndex}", DownloadChunk)
            .RequireAuthorization(CistaAuthorities.VolumeAccess);
        e2ee.MapPatch("/{volumeName}/finalize-file/{fileId}", FinalizeFile)
            .RequireAuthorization(CistaAuthorities.VolumeAccess);
        e2ee.MapDelete("/{volumeName}/files/{fileId}", DeleteFile)
            .RequireAuthorization(CistaAuthorities.VolumeAccess);
        e2ee.MapGet("/{volumeName}/files", ListFiles)
            .RequireAuthorization(CistaAuthorities.VolumeAccess);
        e2ee.MapGet("/{volumeName}/stats", GetStats)
            .RequireAuthorization(CistaAuthorities.VolumeAccess);

        // ---- オーナー限定操作（VolumeOwner ポリシー） ----
        e2ee.MapPost("/{volumeName}/add-wrapped-key", AddWrappedKey)
            .RequireAuthorization(CistaAuthorities.VolumeOwner);
        e2ee.MapGet("/{volumeName}/group-members", GetGroupMembers)
            .RequireAuthorization(CistaAuthorities.VolumeOwner);
        e2ee.MapPost("/{volumeName}/add-wrapped-keys-batch", AddWrappedKeysBatch)
            .RequireAuthorization(CistaAuthorities.VolumeOwner);
        e2ee.MapPut("/{volumeName}/quota/{username}", SetQuota)
            .RequireAuthorization(CistaAuthorities.VolumeOwner);

        // ---- ECDH public key management ----
        e2ee.MapGet("/public-key/{username}", GetPublicKey);
        e2ee.MapPut("/my-public-key", SetMyPublicKey);

        // ---- Group E2EE volume ----
        e2ee.MapPost("/create-group-volume", CreateGroupVolume);

        // ---- Invitation ----
        e2ee.MapPost("/invitations", CreateInvitation);
        e2ee.MapGet("/invitations/{invitationId}", GetInvitation);
        e2ee.MapPost("/invitations/{invitationId}/accept", AcceptInvitation);

        return e2ee;
    }

    private static async Task<IResult> CreateVolume(E2eeCreateVolumeRequest req, VolumeService volumeService, HttpContext ctx)
    {
        string username = ctx.User.Identity?.Name ?? "";
        if (string.IsNullOrEmpty(username))
            return Results.Unauthorized();

        try
        {
            var info = await volumeService.CreateE2eeAsync(req.VolumeName, username, req.WrappedMasterKey, req.ChunkSize);
            return Results.Created($"/api/v1/e2ee/{req.VolumeName}/mount", info);
        }
        catch (VolumeException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private static async Task<IResult> Mount(string volumeName, VolumeService volumeService, HttpContext ctx)
    {
        string username = ctx.User.Identity?.Name ?? "";
        if (string.IsNullOrEmpty(username))
            return Results.Unauthorized();

        try
        {
            var info = await volumeService.MountE2eeAsync(volumeName, username);
            return Results.Ok(info);
        }
        catch (VolumeException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private static async Task<IResult> GetWrappedKey(string volumeName, string username, VolumeService vs, HttpContext ctx)
    {
        string caller = ctx.User.Identity?.Name ?? "";
        if (string.IsNullOrEmpty(caller))
            return Results.Unauthorized();

        if (caller != username)
            return Results.Forbid();

        // defense-in-depth: ポリシーで VolumeAccess をチェック済みだが
        // アクセス権取消後にラップ鍵が残存するケースを防ぐため再チェック
        if (!await vs.HasAccessAsync(volumeName, caller))
            return Results.Forbid();

        if (!vs.IsMounted(volumeName))
            return Results.NotFound(new { error = "ボリュームがマウントされていません。" });

        try
        {
            var header = await vs.GetVolumeHeaderAsync(volumeName);
            if (!header.UserKeys.TryGetValue(username, out var key))
                return Results.NotFound(new { error = "このユーザーの wrapped key が見つかりません。" });

            return Results.Ok(new
            {
                wrapType = key.WrapType,
                kdf = new
                {
                    algorithm = key.Kdf.Algorithm,
                    iterations = key.Kdf.Iterations,
                    salt = Convert.ToBase64String(key.Kdf.Salt),
                },
                wrappedMasterKey = new
                {
                    algorithm = key.WrappedMasterKey.Algorithm,
                    nonce = Convert.ToBase64String(key.WrappedMasterKey.Nonce),
                    ciphertext = Convert.ToBase64String(key.WrappedMasterKey.Ciphertext),
                    tag = Convert.ToBase64String(key.WrappedMasterKey.Tag),
                },
                ephemeralPublicKey = key.EphemeralPublicKey is not null
                    ? Convert.ToBase64String(key.EphemeralPublicKey) : null,
                chunkSize = header.ChunkSize,
            });
        }
        catch (VolumeException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private static async Task<IResult> CreateFile(string volumeName, E2eeCreateFileRequest req, HttpContext ctx, VolumeService vs, E2eeFileService e2eeFs)
    {
        string username = ctx.User.Identity?.Name ?? "";
        try
        {
            var entry = await e2eeFs.CreateFileAsync(volumeName, req, username, ctx.RequestAborted);
            return Results.Created($"/api/v1/e2ee/{volumeName}/upload-chunk/{entry.FileId}/0", entry);
        }
        catch (FileServiceException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private static async Task<IResult> UploadChunk(string volumeName, string fileId, int chunkIndex,
        HttpRequest request, VolumeService vs, E2eeFileService e2eeFs)
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

    private static async Task<IResult> DownloadChunk(string volumeName, string fileId, int chunkIndex, HttpContext ctx, VolumeService vs, E2eeFileService e2eeFs)
    {
        try
        {
            var (stream, length) = await e2eeFs.DownloadChunkAsync(volumeName, fileId, chunkIndex, ctx.RequestAborted);
            return Results.Stream(stream, "application/octet-stream", null, null, enableRangeProcessing: false);
        }
        catch (FileServiceException ex)
        {
            return Results.NotFound(new { error = ex.Message });
        }
    }

    private static async Task<IResult> FinalizeFile(string volumeName, string fileId, E2eeFinalizeFileRequest req, HttpContext ctx, VolumeService vs, E2eeFileService e2eeFs)
    {
        try
        {
            await e2eeFs.FinalizeFileAsync(volumeName, fileId, req, ctx.RequestAborted);
            return Results.Ok();
        }
        catch (FileServiceException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private static async Task<IResult> DeleteFile(string volumeName, string fileId, HttpContext ctx, VolumeService vs, E2eeFileService e2eeFs)
    {
        try
        {
            await e2eeFs.DeleteFileAsync(volumeName, fileId, ctx.RequestAborted);
            return Results.NoContent();
        }
        catch (FileServiceException ex)
        {
            return Results.NotFound(new { error = ex.Message });
        }
    }

    private static async Task<IResult> ListFiles(string volumeName, HttpContext ctx, VolumeService vs, E2eeFileService e2eeFs)
    {
        try
        {
            return Results.Ok(await e2eeFs.ListFilesAsync(volumeName, ctx.RequestAborted));
        }
        catch (FileServiceException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private static async Task<IResult> AddWrappedKey(string volumeName, E2eeAddWrappedKeyRequest req,
        VolumeService volumeService, HttpContext ctx)
    {
        string granter = ctx.User.Identity?.Name ?? "";
        if (string.IsNullOrEmpty(granter))
            return Results.Unauthorized();

        // 認可ポリシー VolumeOwner は granter がボリュームオーナーであることを保証する。
        // サービス層 (VolumeService.AddE2eeWrappedKeyAsync) で granter == OwnerUser を再確認しているため、
        // ここでは granter と req.Username が一致する必要はない (共有フロー: オーナーが他人宛にラップ鍵を追加する)。

        try
        {
            await volumeService.AddE2eeWrappedKeyAsync(volumeName, granter, req.Username, req.WrappedMasterKey);
            return Results.Ok();
        }
        catch (VolumeException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    // ---- ECDH public key ----

    private static async Task<IResult> GetPublicKey(string username, HttpContext ctx, AccountService accountService)
    {
        string caller = ctx.User.Identity?.Name ?? "";
        if (string.IsNullOrEmpty(caller)) return Results.Unauthorized();

        // 公開鍵は暗号プロトコル上公開を前提とするため、認証済みユーザー間で相互参照を許可。
        // ECDH 鍵共有ワークフローで他ユーザーの公開鍵を取得する必要がある。
        var pubKey = await accountService.GetPublicKeyAsync(username);
        return pubKey is not null
            ? Results.Ok(new { publicKey = pubKey })
            : Results.NotFound(new { error = "公開鍵が登録されていません。" });
    }

    private static async Task<IResult> SetMyPublicKey(SetPublicKeyRequest req, HttpContext ctx, AccountService accountService)
    {
        string username = ctx.User.Identity?.Name ?? "";
        if (string.IsNullOrEmpty(username)) return Results.Unauthorized();
        try
        {
            await accountService.UpdatePublicKeyAsync(username, req.PublicKey);
            return Results.Ok();
        }
        catch (InvalidOperationException ex) { return Results.BadRequest(new { error = ex.Message }); }
    }

    // ---- Group E2EE volume ----

    private static async Task<IResult> CreateGroupVolume(CreateGroupE2eeVolumeRequest req,
        VolumeService vs, HttpContext ctx)
    {
        string username = ctx.User.Identity?.Name ?? "";
        if (string.IsNullOrEmpty(username)) return Results.Unauthorized();
        try
        {
            var info = await vs.CreateGroupE2eeAsync(req.GroupName, username, req.OwnerWrappedKey, req.ChunkSize);
            return Results.Created($"/api/v1/e2ee/{info.Name}/mount", info);
        }
        catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
    }

    private static async Task<IResult> GetGroupMembers(string volumeName, VolumeService vs, HttpContext ctx)
    {
        string username = ctx.User.Identity?.Name ?? "";
        if (string.IsNullOrEmpty(username)) return Results.Unauthorized();
        try
        {
            var members = await vs.GetGroupMembersWithPublicKeysAsync(volumeName, username);
            return Results.Ok(members.Select(m => new { m.Username, m.PublicKey }));
        }
        catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
    }

    private static async Task<IResult> AddWrappedKeysBatch(string volumeName, AddE2eeWrappedKeysBatchRequest req,
        VolumeService vs, HttpContext ctx)
    {
        string username = ctx.User.Identity?.Name ?? "";
        if (string.IsNullOrEmpty(username)) return Results.Unauthorized();
        try
        {
            await vs.AddE2eeWrappedKeysBatchAsync(volumeName, username, req.WrappedKeys);
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

    private static IResult GetInvitation(string invitationId, InvitationService invSvc, HttpContext ctx)
    {
        string caller = ctx.User.Identity?.Name ?? "";
        if (string.IsNullOrEmpty(caller))
            return Results.Unauthorized();

        var record = invSvc.Find(invitationId);
        if (record is null)
            return Results.NotFound(new { error = "招待が見つかりません。" });

        if (record.InviterUsername != caller && !string.Equals(record.TargetUsername, caller, StringComparison.Ordinal))
            return Results.Forbid();

        return Results.Ok(new { record.InvitationId, record.InviterUsername, record.CreatedAt });
    }

    private static IResult AcceptInvitation(string invitationId, AcceptInvitationRequest req,
        InvitationService invSvc, HttpContext ctx)
    {
        string caller = ctx.User.Identity?.Name ?? "";
        if (string.IsNullOrEmpty(caller))
            return Results.Unauthorized();

        var record = invSvc.Find(invitationId);
        if (record is null) return Results.NotFound(new { error = "招待が見つかりません。" });

        if (!string.Equals(record.TargetUsername, caller, StringComparison.Ordinal))
            return Results.Forbid();

        try
        {
            invSvc.SetAcceptedData(invitationId, req.EncryptedPublicKey, req.Nonce);
            // 受諾完了後に招待を削除（再利用防止）
            invSvc.Remove(invitationId);
            return Results.Ok();
        }
        catch (InvalidOperationException ex) { return Results.BadRequest(new { error = ex.Message }); }
    }

    // ---- クオータ ----

    private static async Task<IResult> GetStats(string volumeName, HttpContext ctx, VolumeService vs, E2eeFileService e2eeFs)
    {
        string username = ctx.User.Identity?.Name ?? "";
        if (string.IsNullOrEmpty(username)) return Results.Unauthorized();

        try
        {
            var stats = await e2eeFs.GetStatsAsync(volumeName, username, ctx.RequestAborted);
            return Results.Ok(stats);
        }
        catch (FileServiceException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private static async Task<IResult> SetQuota(string volumeName, string username, E2eeSetQuotaRequest req,
        VolumeService vs, HttpContext ctx)
    {
        try
        {
            await vs.SetUserQuotaAsync(volumeName, username, req.MaxBytes);
            return Results.Ok(new { maxBytes = req.MaxBytes });
        }
        catch (VolumeException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }
}

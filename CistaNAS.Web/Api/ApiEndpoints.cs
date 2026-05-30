using CistaNAS.Web.Authorization;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using StreamingTokenService = CistaNAS.Web.Services.StreamingTokenService;

namespace CistaNAS.Web.Api;

internal static class PathSanitizer
{
    /// <summary>
    /// ユーザー入力のファイルパスをサニタイズし、ディレクトリトラバーサルを防止する。
    /// </summary>
    public static string SanitizeFileName(string raw)
    {
        string decoded;
        try { decoded = Uri.UnescapeDataString(raw.TrimStart('/')); }
        catch (UriFormatException) { throw new FileServiceException("ファイル名に無効なエンコーディングが含まれています。"); }
        string normalized = decoded.Replace('\\', '/');

        // ディレクトリトラバーサル要素を除去
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
}

/// <summary>
/// /api/v1 ルート定義（rclone・RCX 等の外部クライアント向け）。
/// 各エンドポイントは Service へ委譲するのみで、ビジネスロジックを書かない。
/// </summary>
public static class ApiEndpoints
{
    public static IEndpointRouteBuilder MapCistaNasApi(this WebApplication app, IEndpointRouteBuilder api)
    {
        // ---- 認証 ----
        api.MapPost("/auth/setup", async (SetupRequest req, AccountService accountService) =>
        {
            if (await accountService.HasAnyUsersAsync())
                return Results.Conflict(new { error = "初期セットアップは既に完了しています。" });
            await accountService.CreateInitialAdminAsync(req.Username, req.Password);
            return Results.Ok(new { message = "初期管理者を作成しました。" });
        })
        .AllowAnonymous()
        .RequireRateLimiting("auth")
        .WithName("Setup");

        api.MapPost("/auth/login", async (LoginRequest req, AuthService auth) =>
        {
            var res = await auth.AuthenticateAsync(req.Username, req.Password);
            return res is null
                ? Results.Unauthorized()
                : Results.Ok(res);
        })
        .AllowAnonymous()
        .RequireRateLimiting("auth")
        .WithName("Login");

        api.MapPost("/auth/change-password", async (ChangePasswordRequest req, HttpContext ctx, AuthService auth) =>
        {
            string? username = ctx.User.Identity?.Name;
            if (string.IsNullOrEmpty(username)) return Results.Unauthorized();
            bool ok = await auth.ChangePasswordAsync(username, req.OldPassword, req.NewPassword);
            return ok ? Results.Ok() : Results.BadRequest(new { error = "認証に失敗しました。" });
        })
        .WithName("ChangePassword");

        // ---- ボリューム ----
        var volumes = api.MapGroup("/volumes")
            .RequireAuthorization();

        volumes.MapPost("/", async (CreateVolumeRequest req, VolumeService vs, HttpContext ctx) =>
        {
            string? username = ctx.User.Identity?.Name;
            if (string.IsNullOrEmpty(username)) return Results.Unauthorized();
            try
            {
                var info = await vs.CreateAsync(req.Name, username, req.Password, req.Encrypted);
                return Results.Created($"/api/v1/volumes/{Uri.EscapeDataString(req.Name)}", info);
            }
            catch (VolumeException ex) { return Results.Conflict(new { error = ex.Message }); }
        })
        .WithName("CreateVolume");

        volumes.MapPost("/{name}/mount", async (string name, MountRequest req, VolumeService vs, HttpContext ctx) =>
        {
            string? username = ctx.User.Identity?.Name;
            if (string.IsNullOrEmpty(username)) return Results.Unauthorized();
            try
            {
                return Results.Ok(await vs.MountAsync(name, username, req.Password));
            }
            catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .RequireAuthorization("VolumeAccessByName")
        .WithName("MountVolume");

        volumes.MapPost("/{name}/lock", async (string name, VolumeService vs, HttpContext ctx) =>
        {
            try
            {
                string? username = ctx.User.Identity?.Name;
                if (string.IsNullOrEmpty(username)) return Results.Unauthorized();
                await vs.LockAsync(name, username);
                return Results.NoContent();
            }
            catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .RequireAuthorization(CistaAuthorities.VolumeOwner)
        .WithName("LockVolume");

        volumes.MapGet("/", async (VolumeService vs, HttpContext ctx) =>
        {
            string? username = ctx.User.Identity?.Name;
            if (string.IsNullOrEmpty(username)) return Results.Unauthorized();
            var list = await vs.ListForUserAsync(username);
            return Results.Ok(list);
        })
        .WithName("ListVolumes");

        volumes.MapDelete("/{name}", async (string name, VolumeService vs, HttpContext ctx) =>
        {
            string? username = ctx.User.Identity?.Name;
            if (string.IsNullOrEmpty(username)) return Results.Unauthorized();
            bool isAdmin = ctx.User.IsInRole("admin");
            try
            {
                await vs.DeleteVolumeAsync(name, username, isAdmin);
                return Results.NoContent();
            }
            catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .RequireAuthorization(CistaAuthorities.VolumeOwnerOrAdmin)
        .WithName("DeleteVolume");

        volumes.MapPost("/{name}/grant", async (string name, GrantAccessRequest req, HttpContext ctx, VolumeService vs) =>
        {
            try
            {
                string? granter = ctx.User.Identity?.Name;
                if (string.IsNullOrEmpty(granter)) return Results.Unauthorized();
                await vs.GrantAccessAsync(name, granter, req.GranterPassword, req.TargetUsername, req.TargetPassword);
                return Results.Ok();
            }
            catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .RequireAuthorization(CistaAuthorities.VolumeOwner)
        .WithName("GrantAccess");

        volumes.MapPost("/{name}/revoke", async (string name, RevokeAccessRequest req, HttpContext ctx, VolumeService vs) =>
        {
            try
            {
                string? revoker = ctx.User.Identity?.Name;
                if (string.IsNullOrEmpty(revoker)) return Results.Unauthorized();
                await vs.RevokeAccessAsync(name, revoker, req.TargetUsername);
                return Results.Ok();
            }
            catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .RequireAuthorization(CistaAuthorities.VolumeOwner)
        .WithName("RevokeAccess");

        // ---- ファイル ----
        var files = api.MapGroup("/files/{volumeName}")
            .RequireAuthorization(CistaAuthorities.VolumeAccess);

        files.MapGet("/", async (string volumeName, FileService fs, HttpContext ctx) =>
        {
            try
            {
                return Results.Ok(await fs.ListAsync(volumeName));
            }
            catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .WithName("ListFiles");

        files.MapPost("/{*filePath}", async (string volumeName, string filePath, HttpContext ctx, FileService fs) =>
        {
            try
            {
                string fileName = PathSanitizer.SanitizeFileName(filePath);
                long len = ctx.Request.ContentLength ?? 0;
                var stream = ctx.Request.Body;
                var meta = await fs.UploadAsync(volumeName, fileName, stream, len, ctx.RequestAborted);
                return Results.Ok(meta);
            }
            catch (Exception ex) when (ex is VolumeException or FileServiceException)
            { return Results.BadRequest(new { error = ex.Message }); }
        })
        .WithName("UploadFile");

        files.MapGet("/{*filePath}", async (string volumeName, string filePath, FileService fs, HttpContext ctx, CancellationToken ct) =>
        {
            try
            {
                string fileName = PathSanitizer.SanitizeFileName(filePath);
                var dl = await fs.DownloadAsync(volumeName, fileName, ct);
                return Results.Stream(dl.Stream, "application/octet-stream", dl.FileName,
                    enableRangeProcessing: false);
            }
            catch (FileServiceException ex) { return Results.NotFound(new { error = ex.Message }); }
            catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .WithName("DownloadFile");

        files.MapDelete("/{*filePath}", async (string volumeName, string filePath, FileService fs, HttpContext ctx) =>
        {
            try
            {
                string fileName = PathSanitizer.SanitizeFileName(filePath);
                await fs.DeleteAsync(volumeName, fileName);
                return Results.NoContent();
            }
            catch (FileServiceException ex) { return Results.NotFound(new { error = ex.Message }); }
            catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .WithName("DeleteFile");

        // ---- E2EE ----
        api.MapE2eeApi();

        // ---- メディアストリーミング ----
        // ストリーミングトークン発行（認証必須 + ボリュームアクセス権チェック）
        api.MapPost("/stream/token", async (StreamTokenRequest req, HttpContext ctx, StreamingTokenService sts, VolumeService vs) =>
        {
            string? username = ctx.User.Identity?.Name;
            if (string.IsNullOrEmpty(username)) return Results.Unauthorized();
            if (!await vs.HasAccessAsync(req.VolumeName, username)) return Results.Forbid();
            string token = sts.Issue(username, req.VolumeName, req.FileName);
            return Results.Ok(new { token });
        })
        .RequireAuthorization()
        .WithName("IssueStreamToken");

        // ストリーミングエンドポイント（短命トークン認証、Range対応）
        api.MapGet("/stream/{volumeName}/{*filePath}", async (
            string volumeName, string filePath, string? token,
            StreamingTokenService sts, VolumeService vs, FileService fs,
            HttpContext ctx) =>
        {
            // トークン検証 — ユーザー・ボリューム・ファイル名すべて照合
            if (string.IsNullOrEmpty(token)) return Results.Unauthorized();
            var validated = sts.Validate(token);
            if (validated is null) return Results.Unauthorized();
            var (user, vol, file) = validated.Value;
            if (!string.Equals(vol, volumeName, StringComparison.Ordinal)) return Results.Forbid();
            if (!await vs.HasAccessAsync(volumeName, user)) return Results.Forbid();

            try
            {
                string fileName = PathSanitizer.SanitizeFileName(filePath);
                if (!string.Equals(file, fileName, StringComparison.Ordinal)) return Results.Forbid();
                var dl = await fs.DownloadAsync(volumeName, fileName, ctx.RequestAborted);
                return Results.Stream(dl.Stream, "application/octet-stream", dl.FileName,
                    enableRangeProcessing: true);
            }
            catch (FileServiceException) { return Results.NotFound(); }
            catch (VolumeException) { return Results.BadRequest(); }
        })
        .AllowAnonymous()
        .WithName("StreamFile");

        // ---- グループ ----
        var groups = api.MapGroup("/groups")
            .RequireAuthorization();

        groups.MapGet("/", async (GroupService gs, HttpContext ctx) =>
        {
            string? username = ctx.User.Identity?.Name;
            if (string.IsNullOrEmpty(username)) return Results.Unauthorized();
            return Results.Ok(await gs.GetGroupsForUserAsync(username));
        })
            .WithName("ListGroups");

        groups.MapPost("/", async (CreateGroupRequest req, HttpContext ctx, GroupService gs) =>
        {
            string? username = ctx.User.Identity?.Name;
            if (string.IsNullOrEmpty(username)) return Results.Unauthorized();
            try
            {
                await gs.CreateGroupAsync(req.GroupName, username);
                return Results.Created($"/api/v1/groups/{req.GroupName}", null);
            }
            catch (InvalidOperationException ex) { return Results.Conflict(new { error = ex.Message }); }
        })
        .WithName("CreateGroup");

        groups.MapDelete("/{groupName}", async (string groupName, HttpContext ctx, GroupService gs) =>
        {
            string? username = ctx.User.Identity?.Name;
            if (string.IsNullOrEmpty(username)) return Results.Unauthorized();
            try
            {
                await gs.DeleteGroupAsync(groupName, username);
                return Results.NoContent();
            }
            catch (InvalidOperationException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .WithName("DeleteGroup");

        groups.MapPost("/{groupName}/members", async (string groupName, AddGroupMemberRequest req,
            HttpContext ctx, GroupService gs) =>
        {
            string? username = ctx.User.Identity?.Name;
            if (string.IsNullOrEmpty(username)) return Results.Unauthorized();
            try
            {
                await gs.AddMemberAsync(groupName, username, req.Username);
                return Results.Ok();
            }
            catch (InvalidOperationException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .WithName("AddGroupMember");

        groups.MapDelete("/{groupName}/members/{username}", async (string groupName, string username,
            HttpContext ctx, GroupService gs) =>
        {
            string? requester = ctx.User.Identity?.Name;
            if (string.IsNullOrEmpty(requester)) return Results.Unauthorized();
            try
            {
                await gs.RemoveMemberAsync(groupName, requester, username);
                return Results.NoContent();
            }
            catch (InvalidOperationException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .WithName("RemoveGroupMember");

        // ---- ボリューム グループアクセス ----
        volumes.MapPost("/{name}/grant-group", async (string name, GrantGroupAccessRequest req,
            HttpContext ctx, VolumeService vs) =>
        {
            try
            {
                string? granter = ctx.User.Identity?.Name;
                if (string.IsNullOrEmpty(granter)) return Results.Unauthorized();
                await vs.GrantGroupAccessAsync(name, granter, req.GroupName);
                return Results.Ok();
            }
            catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .RequireAuthorization(CistaAuthorities.VolumeOwner)
        .WithName("GrantGroupAccess");

        volumes.MapPost("/{name}/revoke-group", async (string name, GrantGroupAccessRequest req,
            HttpContext ctx, VolumeService vs) =>
        {
            try
            {
                string? revoker = ctx.User.Identity?.Name;
                if (string.IsNullOrEmpty(revoker)) return Results.Unauthorized();
                await vs.RevokeGroupAccessAsync(name, revoker, req.GroupName);
                return Results.Ok();
            }
            catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .RequireAuthorization(CistaAuthorities.VolumeOwner)
        .WithName("RevokeGroupAccess");

        return api;
    }
}

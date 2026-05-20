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
        string decoded = Uri.UnescapeDataString(raw.TrimStart('/'));
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
        api.MapPost("/auth/setup", (SetupRequest req, UserStore users) =>
        {
            if (users.HasAnyUsers)
                return Results.Conflict(new { error = "初期セットアップは既に完了しています。" });
            users.CreateInitialAdmin(req.Username, req.Password);
            return Results.Ok(new { message = "初期管理者を作成しました。" });
        })
        .AllowAnonymous()
        .RequireRateLimiting("auth")
        .WithName("Setup");

        api.MapPost("/auth/login", (LoginRequest req, AuthService auth) =>
        {
            var res = auth.Authenticate(req.Username, req.Password);
            return res is null
                ? Results.Unauthorized()
                : Results.Ok(res);
        })
        .AllowAnonymous()
        .RequireRateLimiting("auth")
        .WithName("Login");

        api.MapPost("/auth/change-password", (ChangePasswordRequest req, HttpContext ctx, AuthService auth) =>
        {
            string? username = ctx.User.Identity?.Name;
            if (string.IsNullOrEmpty(username)) return Results.Unauthorized();
            bool ok = auth.ChangePassword(username, req.OldPassword, req.NewPassword);
            return ok ? Results.Ok() : Results.BadRequest(new { error = "パスワードが正しくありません。" });
        })
        .WithName("ChangePassword");

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

        volumes.MapGet("/", (VolumeService vs, HttpContext ctx) =>
        {
            string? username = ctx.User.Identity?.Name;
            var list = username is not null ? vs.ListForUser(username) : vs.ListAll();
            return Results.Ok(list);
        })
        .WithName("ListVolumes");

        volumes.MapPost("/{name}/grant", (string name, GrantAccessRequest req, HttpContext ctx, VolumeService vs) =>
        {
            try
            {
                string? granter = ctx.User.Identity?.Name;
                if (string.IsNullOrEmpty(granter)) return Results.Unauthorized();
                vs.GrantAccess(name, granter, req.GranterPassword, req.TargetUsername, req.TargetPassword);
                return Results.Ok();
            }
            catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .WithName("GrantAccess");

        volumes.MapPost("/{name}/revoke", (string name, RevokeAccessRequest req, HttpContext ctx, VolumeService vs) =>
        {
            try
            {
                string? revoker = ctx.User.Identity?.Name;
                if (string.IsNullOrEmpty(revoker)) return Results.Unauthorized();
                vs.RevokeAccess(name, revoker, req.TargetUsername);
                return Results.Ok();
            }
            catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .WithName("RevokeAccess");

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
                string fileName = PathSanitizer.SanitizeFileName(filePath);
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
                string fileName = PathSanitizer.SanitizeFileName(filePath);
                var dl = fs.Download(volumeName, fileName);
                return Results.Stream(dl.Stream, "application/octet-stream", dl.FileName,
                    enableRangeProcessing: false);
            }
            catch (FileServiceException ex) { return Results.NotFound(new { error = ex.Message }); }
            catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .WithName("DownloadFile");

        files.MapDelete("/{*filePath}", (string volumeName, string filePath, FileService fs) =>
        {
            try
            {
                string fileName = PathSanitizer.SanitizeFileName(filePath);
                fs.Delete(volumeName, fileName);
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
        api.MapPost("/stream/token", (StreamTokenRequest req, HttpContext ctx, StreamingTokenService sts, VolumeService vs) =>
        {
            string? username = ctx.User.Identity?.Name;
            if (string.IsNullOrEmpty(username)) return Results.Unauthorized();
            if (!vs.HasAccess(req.VolumeName, username)) return Results.Forbid();
            string token = sts.Issue(username, req.VolumeName, req.FileName);
            return Results.Ok(new { token });
        })
        .RequireAuthorization()
        .WithName("IssueStreamToken");

        // ストリーミングエンドポイント（短命トークン認証、Range対応）
        api.MapGet("/stream/{volumeName}/{*filePath}", (
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
            if (!vs.HasAccess(volumeName, user)) return Results.Forbid();

            try
            {
                string fileName = PathSanitizer.SanitizeFileName(filePath);
                if (!string.Equals(file, fileName, StringComparison.Ordinal)) return Results.Forbid();
                var dl = fs.Download(volumeName, fileName);
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

        groups.MapGet("/", (GroupStore gs) =>
            Results.Ok(gs.ListGroups()))
            .WithName("ListGroups");

        groups.MapPost("/", (CreateGroupRequest req, HttpContext ctx, GroupStore gs) =>
        {
            string username = ctx.User.Identity?.Name ?? "";
            try
            {
                gs.CreateGroup(req.GroupName, username);
                return Results.Created($"/api/v1/groups/{req.GroupName}", null);
            }
            catch (InvalidOperationException ex) { return Results.Conflict(new { error = ex.Message }); }
        })
        .WithName("CreateGroup");

        groups.MapDelete("/{groupName}", (string groupName, HttpContext ctx, GroupStore gs) =>
        {
            string username = ctx.User.Identity?.Name ?? "";
            try
            {
                gs.DeleteGroup(groupName, username);
                return Results.NoContent();
            }
            catch (InvalidOperationException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .WithName("DeleteGroup");

        groups.MapPost("/{groupName}/members", (string groupName, AddGroupMemberRequest req,
            HttpContext ctx, GroupStore gs) =>
        {
            string username = ctx.User.Identity?.Name ?? "";
            try
            {
                gs.AddMember(groupName, username, req.Username);
                return Results.Ok();
            }
            catch (InvalidOperationException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .WithName("AddGroupMember");

        groups.MapDelete("/{groupName}/members/{username}", (string groupName, string username,
            HttpContext ctx, GroupStore gs) =>
        {
            string requester = ctx.User.Identity?.Name ?? "";
            try
            {
                gs.RemoveMember(groupName, requester, username);
                return Results.NoContent();
            }
            catch (InvalidOperationException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .WithName("RemoveGroupMember");

        // ---- ボリューム グループアクセス ----
        volumes.MapPost("/{name}/grant-group", (string name, GrantGroupAccessRequest req,
            HttpContext ctx, VolumeService vs) =>
        {
            try
            {
                string granter = ctx.User.Identity?.Name ?? "";
                vs.GrantGroupAccess(name, granter, req.GroupName);
                return Results.Ok();
            }
            catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .WithName("GrantGroupAccess");

        volumes.MapPost("/{name}/revoke-group", (string name, GrantGroupAccessRequest req,
            HttpContext ctx, VolumeService vs) =>
        {
            try
            {
                string revoker = ctx.User.Identity?.Name ?? "";
                vs.RevokeGroupAccess(name, revoker, req.GroupName);
                return Results.Ok();
            }
            catch (VolumeException ex) { return Results.BadRequest(new { error = ex.Message }); }
        })
        .WithName("RevokeGroupAccess");

        return api;
    }
}

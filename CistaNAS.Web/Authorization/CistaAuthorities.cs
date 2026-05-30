namespace CistaNAS.Web.Authorization;

/// <summary>
/// 認可 Authority 名の定数定義。
/// 各 Authority は <see cref="CistaAuthorizationHandler"/> で判定される。
/// </summary>
public static class CistaAuthorities
{
    /// <summary>ユーザーがボリュームへのアクセス権を持っていること。</summary>
    public const string VolumeAccess = "VolumeAccess";

    /// <summary>ユーザーがボリュームのオーナーであること。</summary>
    public const string VolumeOwner = "VolumeOwner";

    /// <summary>ユーザーがボリュームのオーナー、または admin ロールであること。</summary>
    public const string VolumeOwnerOrAdmin = "VolumeOwnerOrAdmin";

    /// <summary>ユーザーが admin ロールであること。</summary>
    public const string AdminOnly = "AdminOnly";
}

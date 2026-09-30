using CistaNAS.Web.Configuration;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.Services;

/// <summary>共有操作の種別。拒否時の HTTP ステータス選択に使う。</summary>
public enum SharingAction
{
    /// <summary>共有を送る側（オーナーが他人へ鍵を配る・招待を作る・グループボリュームを作る）。</summary>
    Send,
    /// <summary>共有を受ける側（wrapped key の受取先・招待ターゲット・GroupKey wrap 対象）。</summary>
    Receive,
    /// <summary>ECDH identity（公開鍵 / identity salt）のセットアップ。</summary>
    SetupEcdh,
}

/// <summary>
/// 共有ポリシー判定の集約ポイント。share / invite / grant / ECDH セットアップ系の
/// 全エンドポイントで server-side enforcement に使う（UI だけで制御しない）。
/// revoke 等のアクセス削除操作は本ポリシーの対象外（常に許可）。
/// </summary>
public interface ISharingPolicy
{
    /// <summary>指定ユーザーが該当操作を実行 / 対象として許容できるか。
    /// 条件: グローバル Sharing.Enabled AND ユーザー単位 SharingEnabled。</summary>
    Task<bool> IsAllowedAsync(SharingAction action, string username);

    /// <summary>グローバル設定のみの即時判定（DB アクセス不要のビュー表示向け）。</summary>
    bool IsGlobalSharingEnabled { get; }
}

public sealed class SharingPolicy(
    IOptions<CistaNasOptions> options,
    AccountService accountService) : ISharingPolicy
{
    private readonly CistaNasOptions _options = options.Value;

    public bool IsGlobalSharingEnabled => _options.Sharing.Enabled;

    public async Task<bool> IsAllowedAsync(SharingAction action, string username)
    {
        if (!_options.Sharing.Enabled) return false;
        if (string.IsNullOrEmpty(username)) return false;
        return await accountService.IsSharingEnabledAsync(username);
    }
}

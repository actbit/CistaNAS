namespace CistaNAS.Web.Configuration;

/// <summary>
/// JWT の HMAC 署名鍵。認証ミドルウェアと AuthService(トークン発行) で
/// 同一の鍵を共有するため Singleton として DI 登録する。
/// </summary>
public sealed class JwtSigningKey(byte[] value)
{
    public byte[] Value { get; } = value;
}

namespace CistaNAS.Testing;

/// <summary>テストが起動した localhost の開発証明書だけを許可する。製品コードでは使用しない。</summary>
internal static class LocalTestHttpClient
{
    public static HttpClient Create(Uri baseAddress)
    {
        if (!baseAddress.IsAbsoluteUri || !baseAddress.IsLoopback)
            throw new ArgumentException("Integration tests require a loopback endpoint.", nameof(baseAddress));
        return new HttpClient(new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (request, _, _, _) => request.RequestUri?.IsLoopback == true,
        }) { BaseAddress = baseAddress };
    }
}

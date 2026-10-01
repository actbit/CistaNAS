namespace CistaNAS.Tests;

[Collection("Aspire")]
public sealed class SecurityHeadersApiTests(AspireFixture fixture)
{
    [Theory]
    [InlineData("/")]
    [InlineData("/js/e2ee.js")]
    [InlineData("/api/v1/volumes")]
    [InlineData("/api/v1/does-not-exist")]
    public async Task ClientSuppliedCsp_CannotDisableResponsePolicy(string path)
    {
        using var baseline = await fixture.Http.GetAsync(path);
        Assert.True(baseline.Headers.TryGetValues("Content-Security-Policy", out var expected));
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.TryAddWithoutValidation("Content-Security-Policy", "default-src * 'unsafe-eval'");
        using var response = await fixture.Http.SendAsync(request);
        Assert.Equal(baseline.StatusCode, response.StatusCode);
        Assert.True(response.Headers.TryGetValues("Content-Security-Policy", out var actual));
        Assert.Equal(expected, actual);
        Assert.Contains("object-src 'none'", Assert.Single(actual));
    }
}

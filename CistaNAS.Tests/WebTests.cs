using System.Net;

namespace CistaNAS.Tests;

/// <summary>
/// AspireFixture を再利用し AppHost の重複起動を回避する Web テスト。
/// </summary>
[Collection("Aspire")]
public class WebTests(AspireFixture fixture)
{
    [Fact]
    public async Task GetWebResourceRootReturnsOkStatusCode()
    {
        var response = await fixture.Http.GetAsync("/");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}

using System.Net;
using System.Net.Http.Json;
using AuthApi.Tests.Infrastructure;

namespace AuthApi.Tests;

public class RateLimitTests
{
    [Fact]
    public async Task Login_TooManyAttempts_Returns429()
    {
        using var factory = new AuthApiFactory(new Dictionary<string, string?> { ["AUTH_RATE_LIMIT_PER_MINUTE"] = "3" });
        using var client = factory.CreateClient();
        var credentials = new { email = "ana@example.com", password = "WrongPassword1" };

        for (var i = 0; i < 3; i++)
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/auth/login", credentials)).StatusCode);

        var blocked = await client.PostAsJsonAsync("/auth/login", credentials);

        Assert.Equal(HttpStatusCode.TooManyRequests, blocked.StatusCode);
    }
}

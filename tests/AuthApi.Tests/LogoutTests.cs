using System.Net;
using System.Net.Http.Json;
using AuthApi.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Tests;

public class LogoutTests : TestBase
{
    private Task<HttpResponseMessage> LogoutAsync(string refreshToken) =>
        Client.PostAsJsonAsync("/auth/logout", new { refreshToken });

    [Fact]
    public async Task Logout_RevokesRefreshToken()
    {
        var login = await RegisterAndLoginAsync("ana@example.com");

        var logout = await LogoutAsync(login.RefreshToken);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        var stored = await WithDbAsync(db => db.RefreshTokens.SingleAsync());
        Assert.NotNull(stored.RevokedAt);

        var refresh = await Client.PostAsJsonAsync("/auth/refresh", new { refreshToken = login.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, refresh.StatusCode);
    }

    [Fact]
    public async Task Logout_OnlyRevokesThatSession()
    {
        var laptop = await RegisterAndLoginAsync("ana@example.com");
        var phone = await LoginAsAsync("ana@example.com");

        await LogoutAsync(laptop.RefreshToken);

        var refresh = await Client.PostAsJsonAsync("/auth/refresh", new { refreshToken = phone.RefreshToken });
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);
    }

    [Fact]
    public async Task Logout_IsIdempotentAndDoesNotRevealUnknownTokens()
    {
        var login = await RegisterAndLoginAsync("ana@example.com");

        Assert.Equal(HttpStatusCode.NoContent, (await LogoutAsync(login.RefreshToken)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await LogoutAsync(login.RefreshToken)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await LogoutAsync("unknown-token")).StatusCode);
    }

    [Fact]
    public async Task Logout_DoesNotInvalidateAlreadyIssuedAccessToken()
    {
        // Comportamiento documentado: el JWT es stateless, sigue valiendo hasta su expiración.
        var login = await RegisterAndLoginAsync("ana@example.com");

        await LogoutAsync(login.RefreshToken);

        var me = await SendAsync(HttpMethod.Get, "/users/me", login.AccessToken);
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
    }
}

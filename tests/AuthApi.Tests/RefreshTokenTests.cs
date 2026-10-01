using System.Net;
using System.Net.Http.Json;
using AuthApi.Auth;
using AuthApi.Auth.Tokens;
using AuthApi.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Tests;

public class RefreshTokenTests : TestBase
{
    private Task<HttpResponseMessage> RefreshAsync(string refreshToken) =>
        Client.PostAsJsonAsync("/auth/refresh", new { refreshToken });

    [Fact]
    public async Task Refresh_WithValidToken_ReturnsNewWorkingCredentials()
    {
        var login = await RegisterAndLoginAsync("ana@example.com");

        var response = await RefreshAsync(login.RefreshToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var refreshed = (await response.Content.ReadFromJsonAsync<TokenResponse>())!;
        Assert.NotEqual(login.AccessToken, refreshed.AccessToken);
        Assert.NotEqual(login.RefreshToken, refreshed.RefreshToken); // rotación

        var me = await SendAsync(HttpMethod.Get, "/users/me", refreshed.AccessToken);
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
    }

    [Fact]
    public async Task Refresh_WithExpiredToken_Returns401()
    {
        var login = await RegisterAndLoginAsync("ana@example.com");

        Factory.Time.Advance(TimeSpan.FromDays(7) + TimeSpan.FromMinutes(1)); // vida: 7 días

        var response = await RefreshAsync(login.RefreshToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Refresh_WithRevokedToken_Returns401()
    {
        var login = await RegisterAndLoginAsync("ana@example.com");
        await WithDbAsync(db => db.RefreshTokens.ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAt, DateTime.UtcNow)));

        var response = await RefreshAsync(login.RefreshToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Refresh_WithUnknownToken_Returns401()
    {
        var response = await RefreshAsync("this-token-was-never-issued");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Refresh_ReusingRotatedToken_Returns401AndRevokesAllSessions()
    {
        var login = await RegisterAndLoginAsync("ana@example.com");
        var rotated = (await (await RefreshAsync(login.RefreshToken)).Content.ReadFromJsonAsync<TokenResponse>())!;

        // Alguien reutiliza el token viejo (p. ej. un atacante que lo robó).
        var reuse = await RefreshAsync(login.RefreshToken);
        Assert.Equal(HttpStatusCode.Unauthorized, reuse.StatusCode);

        // Por seguridad, también se invalidó el token nuevo del usuario legítimo.
        var legit = await RefreshAsync(rotated.RefreshToken);
        Assert.Equal(HttpStatusCode.Unauthorized, legit.StatusCode);
    }

    [Fact]
    public async Task RefreshToken_IsStoredOnlyAsHash()
    {
        var login = await RegisterAndLoginAsync("ana@example.com");

        var stored = await WithDbAsync(db => db.RefreshTokens.SingleAsync());

        Assert.NotEqual(login.RefreshToken, stored.TokenHash);
        Assert.Equal(OpaqueToken.Hash(login.RefreshToken), stored.TokenHash);
    }
}

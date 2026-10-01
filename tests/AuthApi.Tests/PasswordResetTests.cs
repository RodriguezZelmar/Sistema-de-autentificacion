using System.Net;
using System.Net.Http.Json;
using AuthApi.Auth;
using AuthApi.Auth.Tokens;
using AuthApi.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Tests;

public class PasswordResetTests : TestBase
{
    private const string NewPassword = "BrandNew456";

    private async Task<ForgotPasswordResponse> ForgotAsync(string email) =>
        (await (await Client.PostAsJsonAsync("/auth/forgot-password", new { email }))
            .Content.ReadFromJsonAsync<ForgotPasswordResponse>())!;

    private Task<HttpResponseMessage> ResetAsync(string token, string newPassword = NewPassword) =>
        Client.PostAsJsonAsync("/auth/reset-password", new { token, newPassword });

    [Fact]
    public async Task Reset_WithValidToken_ChangesPassword()
    {
        await RegisterAsync("ana@example.com");
        var forgot = await ForgotAsync("ana@example.com");
        Assert.NotNull(forgot.ResetToken); // modo demo: el token viene en la respuesta

        var reset = await ResetAsync(forgot.ResetToken);

        Assert.Equal(HttpStatusCode.NoContent, reset.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await LoginAsync("ana@example.com", ValidPassword)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await LoginAsync("ana@example.com", NewPassword)).StatusCode);
    }

    [Fact]
    public async Task Reset_WithExpiredToken_Returns400()
    {
        await RegisterAsync("ana@example.com");
        var forgot = await ForgotAsync("ana@example.com");

        Factory.Time.Advance(TimeSpan.FromMinutes(16)); // vida: 15 minutos

        var reset = await ResetAsync(forgot.ResetToken!);

        Assert.Equal(HttpStatusCode.BadRequest, reset.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await LoginAsync("ana@example.com", ValidPassword)).StatusCode);
    }

    [Fact]
    public async Task Reset_WithAlreadyUsedToken_Returns400()
    {
        await RegisterAsync("ana@example.com");
        var forgot = await ForgotAsync("ana@example.com");
        await ResetAsync(forgot.ResetToken!);

        var secondUse = await ResetAsync(forgot.ResetToken!, "AnotherPass789");

        Assert.Equal(HttpStatusCode.BadRequest, secondUse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await LoginAsync("ana@example.com", NewPassword)).StatusCode);
    }

    [Fact]
    public async Task Reset_WithUnknownToken_Returns400()
    {
        var reset = await ResetAsync("never-issued-token");

        Assert.Equal(HttpStatusCode.BadRequest, reset.StatusCode);
    }

    [Fact]
    public async Task Reset_WithWeakNewPassword_Returns400AndKeepsTokenUsable()
    {
        await RegisterAsync("ana@example.com");
        var forgot = await ForgotAsync("ana@example.com");

        Assert.Equal(HttpStatusCode.BadRequest, (await ResetAsync(forgot.ResetToken!, "weak")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await ResetAsync(forgot.ResetToken!)).StatusCode);
    }

    [Fact]
    public async Task Reset_RevokesAllRefreshTokens()
    {
        var login = await RegisterAndLoginAsync("ana@example.com");
        var forgot = await ForgotAsync("ana@example.com");

        await ResetAsync(forgot.ResetToken!);

        var refresh = await Client.PostAsJsonAsync("/auth/refresh", new { refreshToken = login.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, refresh.StatusCode);
    }

    [Fact]
    public async Task NewRequest_InvalidatesPreviousToken()
    {
        await RegisterAsync("ana@example.com");
        var first = await ForgotAsync("ana@example.com");
        var second = await ForgotAsync("ana@example.com");

        Assert.Equal(HttpStatusCode.BadRequest, (await ResetAsync(first.ResetToken!)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await ResetAsync(second.ResetToken!)).StatusCode);
    }

    [Fact]
    public async Task Forgot_ForUnknownEmail_ReturnsSameMessageWithoutToken()
    {
        await RegisterAsync("ana@example.com");

        var known = await ForgotAsync("ana@example.com");
        var unknown = await ForgotAsync("nobody@example.com");

        Assert.Equal(known.Message, unknown.Message);
        Assert.Null(unknown.ResetToken);
    }

    [Fact]
    public async Task ResetToken_IsStoredOnlyAsHashAndLinkedToUser()
    {
        await RegisterAsync("ana@example.com");
        var forgot = await ForgotAsync("ana@example.com");

        var stored = await WithDbAsync(db => db.PasswordResetTokens.Include(t => t.User).SingleAsync());

        Assert.Equal(OpaqueToken.Hash(forgot.ResetToken!), stored.TokenHash);
        Assert.Equal("ana@example.com", stored.User.Email);
        Assert.Null(stored.UsedAt);
    }

    [Fact]
    public async Task Forgot_InProductionMode_NeverExposesToken()
    {
        using var factory = new AuthApiFactory(new Dictionary<string, string?> { ["PASSWORD_RESET_EXPOSE_TOKEN"] = "false" });
        using var client = factory.CreateClient();
        await client.PostAsJsonAsync("/auth/register", new { email = "ana@example.com", password = ValidPassword });

        var response = await client.PostAsJsonAsync("/auth/forgot-password", new { email = "ana@example.com" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.DoesNotContain("resetToken", await response.Content.ReadAsStringAsync());
    }
}

using System.Net;
using System.Net.Http.Json;
using AuthApi.Auth;
using AuthApi.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Tests;

public class LoginTests : TestBase
{
    [Fact]
    public async Task Login_WithCorrectCredentials_ReturnsBearerAccessToken()
    {
        await RegisterAsync("ana@example.com");

        var response = await LoginAsync("ANA@example.com"); // el email no distingue mayúsculas

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var tokens = await response.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.Equal("Bearer", tokens!.TokenType);
        Assert.Equal(15 * 60, tokens.ExpiresIn);
        Assert.Equal(3, tokens.AccessToken.Split('.').Length); // header.payload.signature
    }

    [Fact]
    public async Task Login_WithWrongPassword_Returns401()
    {
        await RegisterAsync("ana@example.com");

        var response = await LoginAsync("ana@example.com", "WrongPassword1");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Login_WithUnknownUser_Returns401WithSameMessageAsWrongPassword()
    {
        await RegisterAsync("ana@example.com");

        var unknown = await LoginAsync("nobody@example.com");
        var wrongPassword = await LoginAsync("ana@example.com", "WrongPassword1");

        // Misma respuesta en ambos casos: no se revela si el email está registrado.
        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(
            (await wrongPassword.Content.ReadFromJsonAsync<ProblemBody>())!.Detail,
            (await unknown.Content.ReadFromJsonAsync<ProblemBody>())!.Detail);
    }

    [Fact]
    public async Task Login_WithDisabledAccount_Returns403()
    {
        await RegisterAsync("ana@example.com");
        await WithDbAsync(db => db.Users.Where(u => u.Email == "ana@example.com").ExecuteUpdateAsync(s => s.SetProperty(u => u.IsActive, false)));

        var response = await LoginAsync("ana@example.com");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    private sealed record ProblemBody(int Status, string Title, string Detail);
}

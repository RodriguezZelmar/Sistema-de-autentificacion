using System.Net;
using System.Text;
using AuthApi.Auth.Jwt;
using AuthApi.Config;
using AuthApi.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;

namespace AuthApi.Tests;

/// <summary>
/// AUTENTICACIÓN: GET /users/me solo exige un access token válido.
/// </summary>
public class JwtAuthenticationTests : TestBase
{
    [Fact]
    public async Task ProtectedEndpoint_WithValidToken_Returns200AndCurrentUser()
    {
        var tokens = await RegisterAndLoginAsync("ana@example.com");

        var response = await SendAsync(HttpMethod.Get, "/users/me", tokens.AccessToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("\"email\":\"ana@example.com\"", body);
        Assert.DoesNotContain("passwordHash", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ProtectedEndpoint_WithoutToken_Returns401()
    {
        var response = await SendAsync(HttpMethod.Get, "/users/me", accessToken: null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("required", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task ProtectedEndpoint_WithExpiredToken_Returns401()
    {
        await RegisterAsync("ana@example.com");
        var user = await WithDbAsync(db => db.Users.SingleAsync());

        // Token emitido hace 1 hora con vida de 15 minutos → expiró hace 45 minutos.
        var pastClock = new FakeTimeProvider(DateTimeOffset.UtcNow.AddHours(-1));
        var options = Factory.Services.GetRequiredService<IOptions<AuthOptions>>();
        var expired = new JwtTokenService(options, pastClock).CreateAccessToken(user);

        var response = await SendAsync(HttpMethod.Get, "/users/me", expired.Token);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("expired", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task ProtectedEndpoint_WithMalformedToken_Returns401()
    {
        var response = await SendAsync(HttpMethod.Get, "/users/me", "not-a-jwt");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ProtectedEndpoint_WithTokenSignedWithAnotherSecret_Returns401()
    {
        await RegisterAsync("ana@example.com");
        var user = await WithDbAsync(db => db.Users.SingleAsync());
        var attackerOptions = Options.Create(new AuthOptions { JwtSecret = "attacker-secret-attacker-secret-attacker-secret" });
        var forged = new JwtTokenService(attackerOptions, TimeProvider.System).CreateAccessToken(user);

        var response = await SendAsync(HttpMethod.Get, "/users/me", forged.Token);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ProtectedEndpoint_WithTamperedPayload_Returns401()
    {
        var tokens = await RegisterAndLoginAsync("ana@example.com");

        // El atacante decodifica el payload, se cambia el rol a ADMIN y lo vuelve a codificar,
        // pero no puede recalcular la firma sin JWT_SECRET.
        var parts = tokens.AccessToken.Split('.');
        var payload = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(parts[1]));
        var tampered = Base64UrlEncoder.Encode(payload.Replace("\"USER\"", "\"ADMIN\""));

        var response = await SendAsync(HttpMethod.Get, "/users/me", $"{parts[0]}.{tampered}.{parts[2]}");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ProtectedEndpoint_WithUnsignedAlgNoneToken_Returns401()
    {
        var tokens = await RegisterAndLoginAsync("ana@example.com");
        var payload = tokens.AccessToken.Split('.')[1];
        var header = Base64UrlEncoder.Encode("{\"alg\":\"none\",\"typ\":\"JWT\"}");

        var response = await SendAsync(HttpMethod.Get, "/users/me", $"{header}.{payload}.");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task AccessToken_PayloadContainsIdentityButNoSensitiveData()
    {
        var tokens = await RegisterAndLoginAsync("ana@example.com");

        var payload = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(tokens.AccessToken.Split('.')[1]));

        Assert.Contains("\"sub\"", payload);
        Assert.Contains("\"role\":\"USER\"", payload);
        Assert.Contains("\"exp\"", payload);
        Assert.DoesNotContain("password", payload, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(ValidPassword, payload);
    }
}

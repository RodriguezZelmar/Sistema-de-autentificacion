using System.Net;
using System.Net.Http.Json;
using AuthApi.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Tests;

public class RegistrationTests : TestBase
{
    [Fact]
    public async Task Register_WithValidData_Returns201WithoutPasswordOrHash()
    {
        var response = await RegisterAsync("ana@example.com", name: "Ana");

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("\"email\":\"ana@example.com\"", body);
        Assert.Contains("\"role\":\"USER\"", body);
        Assert.DoesNotContain("password", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(ValidPassword, body);
    }

    [Fact]
    public async Task Register_WithDuplicateEmail_Returns409()
    {
        await RegisterAsync("ana@example.com");

        // Mismo email con otra capitalización: se normaliza, así que también es duplicado.
        var response = await RegisterAsync("  ANA@Example.com ");

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Theory]
    [InlineData("short1")]          // muy corta
    [InlineData("onlyletters")]     // sin números
    [InlineData("1234567890")]      // sin letras
    public async Task Register_WithInvalidPassword_Returns400(string password)
    {
        var response = await RegisterAsync("ana@example.com", password);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, await WithDbAsync(db => db.Users.CountAsync(u => u.Email == "ana@example.com")));
    }

    [Fact]
    public async Task Register_WithInvalidEmail_Returns400()
    {
        var response = await RegisterAsync("not-an-email");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Register_StoresPasswordAsBcryptHash()
    {
        await RegisterAsync("ana@example.com");

        var user = await WithDbAsync(db => db.Users.SingleAsync(u => u.Email == "ana@example.com"));

        Assert.NotEqual(ValidPassword, user.PasswordHash);
        Assert.StartsWith("$2", user.PasswordHash); // prefijo de BCrypt
        Assert.True(BCrypt.Net.BCrypt.Verify(ValidPassword, user.PasswordHash));
    }

    [Fact]
    public async Task Register_IgnoresRoleSentByClient()
    {
        var response = await Client.PostAsJsonAsync("/auth/register",
            new { email = "mallory@example.com", password = ValidPassword, role = "ADMIN" });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var user = await WithDbAsync(db => db.Users.SingleAsync(u => u.Email == "mallory@example.com"));
        Assert.Equal("USER", user.Role);
    }
}

using System.Net;
using System.Net.Http.Json;
using AuthApi.Tests.Infrastructure;
using AuthApi.Users;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Tests;

/// <summary>
/// AUTORIZACIÓN vía HTTP: token válido + permiso → 2xx · token válido sin permiso → 403 · sin token → 401.
/// </summary>
public class AuthorizationTests : TestBase
{
    [Fact]
    public async Task User_WithUsersReadPermission_CanListUsers()
    {
        var user = await RegisterAndLoginAsync("ana@example.com");

        var response = await SendAsync(HttpMethod.Get, "/users", user.AccessToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var list = await response.Content.ReadFromJsonAsync<List<UserResponse>>();
        Assert.Contains(list!, u => u.Email == "ana@example.com");
    }

    [Fact]
    public async Task PermissionProtectedEndpoint_WithoutToken_Returns401NotForbidden()
    {
        var response = await SendAsync(HttpMethod.Get, "/users", accessToken: null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Me_ShowsPermissionsGrantedByRole()
    {
        var user = await RegisterAndLoginAsync("ana@example.com");

        var me = await (await SendAsync(HttpMethod.Get, "/users/me", user.AccessToken))
            .Content.ReadFromJsonAsync<CurrentUserResponse>();

        Assert.Equal("USER", me!.User.Role);
        Assert.Equal(["users:read"], me.Permissions);
    }

    [Theory]
    [InlineData("POST")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    public async Task User_WithoutPermission_Gets403(string method)
    {
        var target = await CreateUserAsync("target@example.com");
        var user = await RegisterAndLoginAsync("ana@example.com");

        var response = method switch
        {
            "POST" => await SendAsync(HttpMethod.Post, "/users", user.AccessToken,
                new { email = "new@example.com", password = ValidPassword, role = "ADMIN" }),
            "PUT" => await SendAsync(HttpMethod.Put, $"/users/{target.Id}", user.AccessToken, new { role = "ADMIN" }),
            _ => await SendAsync(HttpMethod.Delete, $"/users/{target.Id}", user.AccessToken)
        };

        // Autenticada (token válido) pero sin permiso → 403, y nada cambió.
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(2, await WithDbAsync(db => db.Users.CountAsync(u => u.Role == "USER")));
    }

    [Fact]
    public async Task Admin_IsSeededWithAllPermissions()
    {
        var admin = await LoginAsAsync(AuthApiFactory.AdminEmail, AuthApiFactory.AdminPassword);

        var me = await (await SendAsync(HttpMethod.Get, "/users/me", admin.AccessToken))
            .Content.ReadFromJsonAsync<CurrentUserResponse>();

        Assert.Equal("ADMIN", me!.User.Role);
        Assert.Equal(["users:create", "users:delete", "users:read", "users:update"], me.Permissions);
    }

    [Fact]
    public async Task Admin_CanCreateUserWithRole()
    {
        var admin = await LoginAsAsync(AuthApiFactory.AdminEmail, AuthApiFactory.AdminPassword);

        var response = await SendAsync(HttpMethod.Post, "/users", admin.AccessToken,
            new { email = "second-admin@example.com", password = ValidPassword, role = "ADMIN" });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("ADMIN", (await response.Content.ReadFromJsonAsync<UserResponse>())!.Role);
    }

    [Fact]
    public async Task Admin_CanUpdateUser_AndRoleChangeRevokesTheirSessions()
    {
        var ana = await RegisterAndLoginAsync("ana@example.com");
        var anaId = (await WithDbAsync(db => db.Users.SingleAsync(u => u.Email == "ana@example.com"))).Id;
        var admin = await LoginAsAsync(AuthApiFactory.AdminEmail, AuthApiFactory.AdminPassword);

        var response = await SendAsync(HttpMethod.Put, $"/users/{anaId}", admin.AccessToken,
            new { name = "Ana Admin", role = "ADMIN" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var updated = await response.Content.ReadFromJsonAsync<UserResponse>();
        Assert.Equal("ADMIN", updated!.Role);
        Assert.Equal("Ana Admin", updated.Name);

        // Su refresh token viejo ya no sirve: debe volver a loguearse para obtener un token con el rol nuevo.
        var refresh = await Client.PostAsJsonAsync("/auth/refresh", new { refreshToken = ana.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, refresh.StatusCode);
    }

    [Fact]
    public async Task Admin_CanDeleteUser()
    {
        var target = await CreateUserAsync("target@example.com");
        var admin = await LoginAsAsync(AuthApiFactory.AdminEmail, AuthApiFactory.AdminPassword);

        var response = await SendAsync(HttpMethod.Delete, $"/users/{target.Id}", admin.AccessToken);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.False(await WithDbAsync(db => db.Users.AnyAsync(u => u.Id == target.Id)));
    }

    [Fact]
    public async Task Admin_CannotDeleteThemselves()
    {
        var admin = await LoginAsAsync(AuthApiFactory.AdminEmail, AuthApiFactory.AdminPassword);
        var adminId = (await WithDbAsync(db => db.Users.SingleAsync(u => u.Role == "ADMIN"))).Id;

        var response = await SendAsync(HttpMethod.Delete, $"/users/{adminId}", admin.AccessToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Admin_CreatingUserWithUnknownRole_Returns400()
    {
        var admin = await LoginAsAsync(AuthApiFactory.AdminEmail, AuthApiFactory.AdminPassword);

        var response = await SendAsync(HttpMethod.Post, "/users", admin.AccessToken,
            new { email = "x@example.com", password = ValidPassword, role = "SUPERUSER" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private async Task<UserResponse> CreateUserAsync(string email)
    {
        var response = await RegisterAsync(email);
        return (await response.Content.ReadFromJsonAsync<UserResponse>())!;
    }
}

using System.Net;
using System.Net.Http.Json;
using AuthApi.Tests.Infrastructure;
using AuthApi.Users;

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
}

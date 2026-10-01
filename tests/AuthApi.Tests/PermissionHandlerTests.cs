using System.Security.Claims;
using AuthApi.Authorization;
using Microsoft.AspNetCore.Authorization;

namespace AuthApi.Tests;

/// <summary>
/// Tests unitarios (sin HTTP) del mapa Role → Permisos y del handler de autorización.
/// </summary>
public class PermissionHandlerTests
{
    [Fact]
    public void UserRole_OnlyHasReadPermission()
    {
        Assert.Equal(new HashSet<string> { Permissions.UsersRead }, RolePermissions.For(Roles.User));
    }

    [Fact]
    public void AdminRole_HasAllUserPermissions()
    {
        Assert.Equal(
            new HashSet<string> { Permissions.UsersRead, Permissions.UsersCreate, Permissions.UsersUpdate, Permissions.UsersDelete },
            RolePermissions.For(Roles.Admin));
    }

    [Fact]
    public void UnknownRole_HasNoPermissions()
    {
        Assert.Empty(RolePermissions.For("HACKER"));
    }

    [Theory]
    [InlineData(Roles.User, Permissions.UsersRead, true)]
    [InlineData(Roles.User, Permissions.UsersDelete, false)]
    [InlineData(Roles.Admin, Permissions.UsersDelete, true)]
    [InlineData("HACKER", Permissions.UsersRead, false)]
    public async Task Handler_SucceedsOnlyWhenRoleGrantsPermission(string role, string permission, bool expected)
    {
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim("role", role)], authenticationType: "Bearer"));
        var requirement = new PermissionRequirement(permission);
        var context = new AuthorizationHandlerContext([requirement], user, resource: null);

        await new PermissionAuthorizationHandler().HandleAsync(context);

        Assert.Equal(expected, context.HasSucceeded);
    }
}

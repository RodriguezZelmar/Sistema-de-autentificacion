using AuthApi.Auth.Jwt;
using Microsoft.AspNetCore.Authorization;

namespace AuthApi.Authorization;

/// <summary>
/// Decide si el usuario YA AUTENTICADO tiene el permiso que pide el endpoint.
/// No valida tokens ni firmas: eso ya lo hizo la autenticación.
/// Solo mira la identidad resultante (el claim "role") y la traduce a permisos.
/// </summary>
public sealed class PermissionAuthorizationHandler : AuthorizationHandler<PermissionRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
    {
        var role = context.User.FindFirst(JwtTokenService.RoleClaim)?.Value;

        if (role is not null && RolePermissions.RoleHasPermission(role, requirement.Permission))
            context.Succeed(requirement);

        // Si no se llama a Succeed, la autorización falla → el middleware responde 403 Forbidden.
        return Task.CompletedTask;
    }
}

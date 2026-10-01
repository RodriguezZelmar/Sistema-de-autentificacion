using Microsoft.AspNetCore.Authorization;

namespace AuthApi.Authorization;

/// <summary>
/// Guard de AUTORIZACIÓN para un endpoint:  [RequirePermission(Permissions.UsersDelete)]
///
/// Hereda de [Authorize], así que primero exige estar autenticado (sin token válido → 401) y
/// después agrega el requisito de permiso (autenticado pero sin permiso → 403).
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public sealed class RequirePermissionAttribute(string permission) : AuthorizeAttribute, IAuthorizationRequirementData
{
    public string Permission { get; } = permission;

    public IEnumerable<IAuthorizationRequirement> GetRequirements() => [new PermissionRequirement(Permission)];
}

public sealed record PermissionRequirement(string Permission) : IAuthorizationRequirement;

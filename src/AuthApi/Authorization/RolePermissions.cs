namespace AuthApi.Authorization;

/// <summary>
/// Role → conjunto de permisos → acciones que puede realizar.
///
/// El mapa vive en el código (no en la base) porque cambia junto con el código que define
/// los endpoints. Para administrar permisos en tiempo de ejecución se moverían a tablas
/// Role / Permission / RolePermission sin tocar los endpoints.
/// </summary>
public static class RolePermissions
{
    private static readonly Dictionary<string, IReadOnlySet<string>> Map = new()
    {
        [Roles.User] = new HashSet<string>
        {
            Permissions.UsersRead
        },
        [Roles.Admin] = new HashSet<string>
        {
            Permissions.UsersRead,
            Permissions.UsersCreate,
            Permissions.UsersUpdate,
            Permissions.UsersDelete
        }
    };

    public static IReadOnlySet<string> For(string role) =>
        Map.TryGetValue(role, out var permissions) ? permissions : new HashSet<string>();

    public static bool RoleHasPermission(string role, string permission) => For(role).Contains(permission);
}

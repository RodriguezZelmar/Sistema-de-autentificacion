namespace AuthApi.Authorization;

/// <summary>
/// Permisos = acciones concretas sobre un recurso, con formato "recurso:acción".
/// Los endpoints piden PERMISOS, no roles: así un endpoint no cambia si mañana aparece un rol nuevo.
/// </summary>
public static class Permissions
{
    public const string UsersRead = "users:read";
    public const string UsersCreate = "users:create";
    public const string UsersUpdate = "users:update";
    public const string UsersDelete = "users:delete";
}

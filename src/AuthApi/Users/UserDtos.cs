using System.ComponentModel.DataAnnotations;
using AuthApi.Auth.Validation;
using AuthApi.Data.Entities;

namespace AuthApi.Users;

/// <summary>
/// Representación pública de un usuario. Es la ÚNICA forma en que un usuario sale de la API:
/// nunca se serializa la entidad directamente, así PasswordHash no puede filtrarse por accidente.
/// </summary>
public sealed record UserResponse(Guid Id, string Email, string? Name, string Role, bool IsActive, DateTime CreatedAt)
{
    public static UserResponse From(User user) =>
        new(user.Id, user.Email, user.Name, user.Role, user.IsActive, user.CreatedAt);
}

/// <summary>Respuesta de /users/me: el usuario y los permisos que le da su rol.</summary>
public sealed record CurrentUserResponse(UserResponse User, IReadOnlyCollection<string> Permissions);

/// <summary>
/// Alta de usuario por un administrador (requiere users:create).
/// A diferencia del registro público, acá SÍ se puede elegir el rol: el permiso lo controla.
/// </summary>
public sealed record CreateUserRequest(
    [Required, EmailAddress, MaxLength(254)] string Email,
    [Required, PasswordPolicy] string Password,
    [MaxLength(100)] string? Name,
    [MaxLength(20)] string? Role);

/// <summary>Actualiza los campos enviados (los null no se modifican). Requiere users:update.</summary>
public sealed record UpdateUserRequest(
    [MaxLength(100)] string? Name,
    [MaxLength(20)] string? Role,
    bool? IsActive);

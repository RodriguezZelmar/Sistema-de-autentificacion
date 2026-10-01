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

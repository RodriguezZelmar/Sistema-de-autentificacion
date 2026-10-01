using AuthApi.Authorization;

namespace AuthApi.Data.Entities;

public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Siempre normalizado (trim + minúsculas) para que "Ana@X.com" y "ana@x.com" sean el mismo usuario.</summary>
    public required string Email { get; set; }

    public string? Name { get; set; }

    /// <summary>Hash BCrypt (incluye algoritmo, costo y salt). La contraseña en texto plano nunca se guarda.</summary>
    public required string PasswordHash { get; set; }

    public string Role { get; set; } = Roles.User;

    /// <summary>Un usuario desactivado no puede hacer login ni refrescar tokens.</summary>
    public bool IsActive { get; set; } = true;

    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

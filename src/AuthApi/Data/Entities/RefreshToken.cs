namespace AuthApi.Data.Entities;

/// <summary>
/// Refresh token emitido a un usuario. Solo se guarda el hash SHA-256 del token:
/// si alguien roba la base de datos no obtiene tokens utilizables.
/// </summary>
public class RefreshToken
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public User User { get; set; } = null!;

    public required string TokenHash { get; set; }
    public DateTime ExpiresAt { get; set; }

    /// <summary>null = vigente. Se completa en logout, en rotación (refresh) o al cambiar la contraseña.</summary>
    public DateTime? RevokedAt { get; set; }

    public DateTime CreatedAt { get; set; }

    public bool IsActive(DateTime now) => RevokedAt is null && ExpiresAt > now;
}

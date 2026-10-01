namespace AuthApi.Data.Entities;

/// <summary>
/// Token de recuperación de contraseña: temporal, de un solo uso y asociado a un usuario.
/// Igual que los refresh tokens, solo se guarda su hash.
/// </summary>
public class PasswordResetToken
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public User User { get; set; } = null!;

    public required string TokenHash { get; set; }
    public DateTime ExpiresAt { get; set; }

    /// <summary>null = sin usar. Una vez completado, el token ya no sirve.</summary>
    public DateTime? UsedAt { get; set; }

    public DateTime CreatedAt { get; set; }

    public bool IsUsable(DateTime now) => UsedAt is null && ExpiresAt > now;
}

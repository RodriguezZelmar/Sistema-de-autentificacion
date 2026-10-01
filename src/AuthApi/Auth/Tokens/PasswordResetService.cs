using AuthApi.Auth.Passwords;
using AuthApi.Common;
using AuthApi.Config;
using AuthApi.Data;
using AuthApi.Data.Entities;
using AuthApi.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthApi.Auth.Tokens;

public sealed record IssuedResetToken(string Token, DateTime ExpiresAt);

/// <summary>
/// Recuperación de contraseña con tokens temporales, de un solo uso y asociados a un usuario.
/// </summary>
public sealed class PasswordResetService(
    AppDbContext db,
    IPasswordHasher hasher,
    RefreshTokenService refreshTokens,
    IOptions<AuthOptions> options,
    TimeProvider time,
    ILogger<PasswordResetService> logger)
{
    private DateTime Now => time.GetUtcNow().UtcDateTime;

    /// <summary>
    /// Genera un token de recuperación. Devuelve null si el email no corresponde a un usuario activo
    /// (el controller responde igual en ambos casos para no revelar qué emails existen).
    /// </summary>
    public async Task<IssuedResetToken?> RequestAsync(string email, CancellationToken ct)
    {
        var normalized = UserService.NormalizeEmail(email);
        var user = await db.Users.SingleOrDefaultAsync(u => u.Email == normalized && u.IsActive, ct);
        if (user is null)
            return null;

        // Solo el último token pedido es válido: se descartan los anteriores que no se usaron.
        await db.PasswordResetTokens
            .Where(t => t.UserId == user.Id && t.UsedAt == null)
            .ExecuteDeleteAsync(ct);

        var token = OpaqueToken.Generate();
        var entity = new PasswordResetToken
        {
            UserId = user.Id,
            TokenHash = OpaqueToken.Hash(token), // igual que los refresh tokens: solo el hash en la base
            CreatedAt = Now,
            ExpiresAt = Now.AddMinutes(options.Value.PasswordResetTokenMinutes)
        };
        db.PasswordResetTokens.Add(entity);
        await db.SaveChangesAsync(ct);

        // En una aplicación real, acá se enviaría un email con un link que contiene el token.
        logger.LogInformation("Password reset requested for user {UserId}", user.Id);
        return new IssuedResetToken(token, entity.ExpiresAt);
    }

    /// <summary>Valida el token, cambia la contraseña y cierra todas las sesiones del usuario.</summary>
    public async Task ResetAsync(string token, string newPassword, CancellationToken ct)
    {
        var hash = OpaqueToken.Hash(token);
        var stored = await db.PasswordResetTokens.Include(t => t.User).SingleOrDefaultAsync(t => t.TokenHash == hash, ct);

        // Mismo error para inexistente, expirado o ya usado.
        if (stored is null || !stored.IsUsable(Now))
            throw InvalidToken();

        await using var transaction = await db.Database.BeginTransactionAsync(ct);

        // Marca el token como usado de forma ATÓMICA: el UPDATE solo afecta la fila si UsedAt sigue en null.
        // Si dos requests llegan a la vez con el mismo token, solo uno actualiza 1 fila; el otro, 0.
        var now = Now;
        var claimed = await db.PasswordResetTokens
            .Where(t => t.Id == stored.Id && t.UsedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.UsedAt, now), ct);
        if (claimed == 0)
            throw InvalidToken();

        stored.User.PasswordHash = hasher.Hash(newPassword);
        stored.User.UpdatedAt = now;
        await db.SaveChangesAsync(ct);

        // Si alguien tenía una sesión abierta con la contraseña vieja (¿un atacante?), se cierra.
        await refreshTokens.RevokeAllForUserAsync(stored.UserId, ct);

        await transaction.CommitAsync(ct);
        logger.LogInformation("Password reset completed for user {UserId}", stored.UserId);
    }

    private static ApiException InvalidToken() => ApiException.BadRequest("Invalid or expired password reset token.");
}

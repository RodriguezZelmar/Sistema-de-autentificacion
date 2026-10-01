using AuthApi.Common;
using AuthApi.Config;
using AuthApi.Data;
using AuthApi.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthApi.Auth.Tokens;

public sealed record IssuedRefreshToken(string Token, DateTime ExpiresAt);

/// <summary>
/// Ciclo de vida de los refresh tokens: emisión, rotación y revocación.
/// El access token (JWT) es stateless; el refresh token es stateful (vive en la base), y por eso SÍ se puede revocar.
/// </summary>
public sealed class RefreshTokenService(
    AppDbContext db,
    IOptions<AuthOptions> options,
    TimeProvider time,
    ILogger<RefreshTokenService> logger)
{
    private DateTime Now => time.GetUtcNow().UtcDateTime;

    /// <summary>Crea un refresh token nuevo. Devuelve el valor en claro UNA sola vez; en la base queda solo el hash.</summary>
    public async Task<IssuedRefreshToken> IssueAsync(User user, CancellationToken ct)
    {
        var token = OpaqueToken.Generate();
        var entity = new RefreshToken
        {
            UserId = user.Id,
            TokenHash = OpaqueToken.Hash(token),
            CreatedAt = Now,
            ExpiresAt = Now.AddDays(options.Value.RefreshTokenDays)
        };

        db.RefreshTokens.Add(entity);
        await db.SaveChangesAsync(ct);
        return new IssuedRefreshToken(token, entity.ExpiresAt);
    }

    /// <summary>
    /// Rotación: valida el refresh token, lo revoca y emite uno nuevo.
    /// Cada refresh token sirve UNA sola vez.
    /// </summary>
    public async Task<(User User, IssuedRefreshToken NewToken)> RotateAsync(string token, CancellationToken ct)
    {
        var stored = await FindAsync(token, ct) ?? throw InvalidToken();

        if (stored.RevokedAt is not null)
        {
            // Detección de reutilización: un token ya rotado/revocado no debería volver a usarse.
            // Si aparece, puede que lo hayan robado → se cierran todas las sesiones del usuario.
            logger.LogWarning("Revoked refresh token reused for user {UserId}; revoking all sessions", stored.UserId);
            await RevokeAllForUserAsync(stored.UserId, ct);
            throw InvalidToken();
        }

        if (stored.ExpiresAt <= Now)
            throw InvalidToken();

        if (!stored.User.IsActive)
            throw ApiException.Forbidden("This account is disabled.");

        stored.RevokedAt = Now;
        var newToken = await IssueAsync(stored.User, ct); // guarda la revocación y el token nuevo juntos
        return (stored.User, newToken);
    }

    /// <summary>Logout: revoca el refresh token indicado. Es idempotente (revocar dos veces no falla).</summary>
    public async Task RevokeAsync(string token, CancellationToken ct)
    {
        var stored = await FindAsync(token, ct);
        if (stored is null || stored.RevokedAt is not null)
            return;

        stored.RevokedAt = Now;
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Revoca todas las sesiones activas de un usuario (reutilización detectada, cambio de contraseña…).</summary>
    public Task<int> RevokeAllForUserAsync(Guid userId, CancellationToken ct)
    {
        var now = Now;
        return db.RefreshTokens
            .Where(t => t.UserId == userId && t.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAt, now), ct);
    }

    private Task<RefreshToken?> FindAsync(string token, CancellationToken ct)
    {
        var hash = OpaqueToken.Hash(token);
        return db.RefreshTokens.Include(t => t.User).SingleOrDefaultAsync(t => t.TokenHash == hash, ct);
    }

    // Mismo mensaje para inexistente, expirado o revocado: no se da información extra a un atacante.
    private static ApiException InvalidToken() => ApiException.Unauthorized("Invalid or expired refresh token.");
}

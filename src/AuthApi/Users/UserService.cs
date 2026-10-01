using AuthApi.Auth.Passwords;
using AuthApi.Auth.Tokens;
using AuthApi.Authorization;
using AuthApi.Common;
using AuthApi.Data;
using AuthApi.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Users;

/// <summary>
/// Gestión de usuarios (el "almacén de identidades"). La usan tanto el registro público
/// (AuthService, siempre con rol USER) como los endpoints de administración.
/// </summary>
public sealed class UserService(
    AppDbContext db,
    IPasswordHasher hasher,
    RefreshTokenService refreshTokens,
    TimeProvider time)
{
    public static string NormalizeEmail(string email) => email.Trim().ToLowerInvariant();

    public async Task<User> CreateAsync(string email, string password, string? name, string role, CancellationToken ct)
    {
        email = NormalizeEmail(email);
        role = ValidateRole(role);

        if (await db.Users.AnyAsync(u => u.Email == email, ct))
            throw ApiException.Conflict("Email is already registered.");

        var now = time.GetUtcNow().UtcDateTime;
        var user = new User
        {
            Email = email,
            Name = string.IsNullOrWhiteSpace(name) ? null : name.Trim(),
            PasswordHash = hasher.Hash(password),
            Role = role,
            CreatedAt = now,
            UpdatedAt = now
        };

        db.Users.Add(user);
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            // Dos registros simultáneos con el mismo email pueden pasar el AnyAsync de arriba;
            // el índice único de la base es la garantía final.
            throw ApiException.Conflict("Email is already registered.");
        }

        return user;
    }

    public async Task<List<User>> ListAsync(CancellationToken ct) =>
        await db.Users.AsNoTracking().OrderBy(u => u.CreatedAt).ToListAsync(ct);

    public async Task<User> GetByIdAsync(Guid id, CancellationToken ct) =>
        await db.Users.FindAsync([id], ct) ?? throw ApiException.NotFound("User not found.");

    public async Task<User> UpdateAsync(Guid id, UpdateUserRequest request, Guid actingUserId, CancellationToken ct)
    {
        var user = await GetByIdAsync(id, ct);
        var newRole = request.Role is null ? user.Role : ValidateRole(request.Role);
        var newIsActive = request.IsActive ?? user.IsActive;

        var roleChanged = newRole != user.Role;
        var disabled = user.IsActive && !newIsActive;

        // Evita que un admin se quite sus propios permisos o se bloquee (y quede el sistema sin admin).
        if (id == actingUserId && (roleChanged || disabled))
            throw ApiException.BadRequest("You cannot change your own role or disable your own account.");

        if (request.Name is not null)
            user.Name = string.IsNullOrWhiteSpace(request.Name) ? null : request.Name.Trim();
        user.Role = newRole;
        user.IsActive = newIsActive;
        user.UpdatedAt = time.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(ct);

        // Si cambió el rol o se desactivó la cuenta, se cierran sus sesiones: no podrá refrescar tokens
        // con el rol viejo. (Su access token actual sigue vigente hasta expirar, como máximo 15 min.)
        if (roleChanged || disabled)
            await refreshTokens.RevokeAllForUserAsync(user.Id, ct);

        return user;
    }

    public async Task DeleteAsync(Guid id, Guid actingUserId, CancellationToken ct)
    {
        if (id == actingUserId)
            throw ApiException.BadRequest("You cannot delete your own account.");

        var user = await GetByIdAsync(id, ct);
        db.Users.Remove(user); // sus refresh tokens y tokens de recuperación se borran en cascada
        await db.SaveChangesAsync(ct);
    }

    private static string ValidateRole(string role)
    {
        var normalized = role.Trim().ToUpperInvariant();
        return Roles.All.Contains(normalized)
            ? normalized
            : throw ApiException.BadRequest($"Unknown role '{role}'. Valid roles: {string.Join(", ", Roles.All)}.");
    }
}

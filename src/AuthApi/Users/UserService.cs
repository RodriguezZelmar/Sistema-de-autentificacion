using AuthApi.Auth.Passwords;
using AuthApi.Common;
using AuthApi.Data;
using AuthApi.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Users;

/// <summary>
/// Gestión de usuarios (el "almacén de identidades"). La usan tanto el registro público
/// (AuthService, siempre con rol USER) como los endpoints de administración.
/// </summary>
public sealed class UserService(AppDbContext db, IPasswordHasher hasher, TimeProvider time)
{
    public static string NormalizeEmail(string email) => email.Trim().ToLowerInvariant();

    public async Task<User> CreateAsync(string email, string password, string? name, string role, CancellationToken ct)
    {
        email = NormalizeEmail(email);

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
}

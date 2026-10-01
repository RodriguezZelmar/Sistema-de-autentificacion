using AuthApi.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<PasswordResetToken> PasswordResetTokens => Set<PasswordResetToken>();

    protected override void OnModelCreating(ModelBuilder model)
    {
        model.Entity<User>(user =>
        {
            user.Property(u => u.Email).HasMaxLength(254);
            // Índice único: la base de datos garantiza que no haya emails duplicados,
            // incluso si dos registros simultáneos pasan la verificación previa del service.
            user.HasIndex(u => u.Email).IsUnique();
            user.Property(u => u.Name).HasMaxLength(100);
            user.Property(u => u.Role).HasMaxLength(20);
        });

        model.Entity<RefreshToken>(token =>
        {
            token.HasIndex(t => t.TokenHash).IsUnique();
            token.HasOne(t => t.User).WithMany().HasForeignKey(t => t.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        model.Entity<PasswordResetToken>(token =>
        {
            token.HasIndex(t => t.TokenHash).IsUnique();
            token.HasOne(t => t.User).WithMany().HasForeignKey(t => t.UserId).OnDelete(DeleteBehavior.Cascade);
        });
    }
}

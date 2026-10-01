using AuthApi.Auth.Validation;
using AuthApi.Authorization;
using AuthApi.Users;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Data;

/// <summary>
/// Prepara la base de datos al arrancar:
/// 1. Aplica las migraciones pendientes (crea la base desde cero si no existe).
/// 2. Crea el administrador de demo si ADMIN_EMAIL y ADMIN_PASSWORD están definidas.
///
/// Es la ÚNICA vía para obtener un ADMIN sin tener ya uno: el registro público siempre asigna USER.
/// En producción basta con no definir esas variables.
/// </summary>
public static class DatabaseInitializer
{
    public static async Task InitializeAsync(IServiceProvider services)
    {
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        await db.Database.MigrateAsync();
        await SeedAdminAsync(scope.ServiceProvider);
    }

    private static async Task SeedAdminAsync(IServiceProvider services)
    {
        var config = services.GetRequiredService<IConfiguration>();
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger(typeof(DatabaseInitializer));
        var email = config["ADMIN_EMAIL"];
        var password = config["ADMIN_PASSWORD"];

        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
            return;

        if (!new PasswordPolicyAttribute().IsValid(password))
            throw new InvalidOperationException("ADMIN_PASSWORD does not satisfy the password policy.");

        var db = services.GetRequiredService<AppDbContext>();
        var normalized = UserService.NormalizeEmail(email);
        if (await db.Users.AnyAsync(u => u.Email == normalized))
            return;

        var admin = await services.GetRequiredService<UserService>()
            .CreateAsync(email, password, "Administrator", Roles.Admin, CancellationToken.None);
        logger.LogInformation("Seeded demo admin user {UserId}", admin.Id);
    }
}

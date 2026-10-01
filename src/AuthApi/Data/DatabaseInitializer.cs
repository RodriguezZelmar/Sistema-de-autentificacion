using Microsoft.EntityFrameworkCore;

namespace AuthApi.Data;

/// <summary>
/// Prepara la base de datos al arrancar: aplica las migraciones pendientes
/// (crea la base desde cero si no existe).
/// </summary>
public static class DatabaseInitializer
{
    public static async Task InitializeAsync(IServiceProvider services)
    {
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        await db.Database.MigrateAsync();
    }
}

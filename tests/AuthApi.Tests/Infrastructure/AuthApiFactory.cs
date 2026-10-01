using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Time.Testing;

namespace AuthApi.Tests.Infrastructure;

/// <summary>
/// Levanta la API real en memoria para cada test, con:
/// - su propia base SQLite temporal (tests aislados entre sí);
/// - un reloj falso (FakeTimeProvider) para simular el paso del tiempo y probar expiraciones;
/// - configuración de test que pisa cualquier valor de un .env local.
/// </summary>
public sealed class AuthApiFactory : WebApplicationFactory<Program>
{
    public const string JwtSecret = "test-only-secret-key-that-is-long-enough-1234567890";
    public const string AdminEmail = "admin@test.local";
    public const string AdminPassword = "AdminPass123";

    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"authapi-test-{Guid.NewGuid():N}.db");

    public FakeTimeProvider Time { get; } = new(DateTimeOffset.UtcNow);

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.ConfigureAppConfiguration(config => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["DATABASE_CONNECTION"] = $"Data Source={_dbPath}",
            ["JWT_SECRET"] = JwtSecret,
            ["JWT_ISSUER"] = "auth-api",
            ["JWT_AUDIENCE"] = "auth-api-clients",
            ["JWT_ACCESS_TOKEN_MINUTES"] = "15",
            ["REFRESH_TOKEN_DAYS"] = "7",
            ["PASSWORD_RESET_TOKEN_MINUTES"] = "15",
            ["PASSWORD_RESET_EXPOSE_TOKEN"] = "true",
            ["BCRYPT_WORK_FACTOR"] = "4", // mínimo de BCrypt: tests rápidos
            ["AUTH_RATE_LIMIT_PER_MINUTE"] = "1000",
            ["ADMIN_EMAIL"] = AdminEmail,
            ["ADMIN_PASSWORD"] = AdminPassword,
        }));

        builder.ConfigureServices(services =>
        {
            services.RemoveAll<TimeProvider>();
            services.AddSingleton<TimeProvider>(Time);
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        SqliteConnection.ClearAllPools();
        try { File.Delete(_dbPath); } catch (IOException) { /* el SO lo limpiará */ }
    }
}

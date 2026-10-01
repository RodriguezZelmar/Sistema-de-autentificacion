using AuthApi.Auth;
using AuthApi.Auth.Passwords;
using AuthApi.Users;

namespace AuthApi.Config;

/// <summary>
/// Punto de entrada del módulo de autenticación/autorización.
/// Program.cs solo llama a <c>AddAuthModule</c>: todo lo que el módulo necesita se registra acá,
/// lo que facilita copiarlo/adaptarlo a otro proyecto.
/// </summary>
public static class AuthModuleExtensions
{
    public static IServiceCollection AddAuthModule(this IServiceCollection services, IConfiguration config)
    {
        services.AddOptions<AuthOptions>()
            .Configure(options => options.Load(config))
            .Validate(o => o.JwtSecret.Length >= 32, "JWT_SECRET must be set and be at least 32 characters long.")
            .Validate(o => o.AccessTokenMinutes > 0 && o.RefreshTokenDays > 0 && o.PasswordResetTokenMinutes > 0,
                "Token lifetimes must be positive.")
            .ValidateOnStart();

        services.AddSingleton<IPasswordHasher, BcryptPasswordHasher>();
        services.AddScoped<UserService>();
        services.AddScoped<AuthService>();

        return services;
    }
}

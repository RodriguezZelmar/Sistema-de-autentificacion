using System.Threading.RateLimiting;
using AuthApi.Auth;
using AuthApi.Auth.Jwt;
using AuthApi.Auth.Passwords;
using AuthApi.Auth.Tokens;
using AuthApi.Authorization;
using AuthApi.Users;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace AuthApi.Config;

/// <summary>
/// Punto de entrada del módulo de autenticación/autorización.
/// Program.cs solo llama a <c>AddAuthModule</c>: todo lo que el módulo necesita se registra acá,
/// lo que facilita copiarlo/adaptarlo a otro proyecto.
/// </summary>
public static class AuthModuleExtensions
{
    public const string AuthRateLimitPolicy = "auth";

    public static IServiceCollection AddAuthModule(this IServiceCollection services, IConfiguration config)
    {
        services.AddOptions<AuthOptions>()
            .Configure(options => options.Load(config))
            .Validate(o => o.JwtSecret.Length >= 32, "JWT_SECRET must be set and be at least 32 characters long.")
            .Validate(o => o.AccessTokenMinutes > 0 && o.RefreshTokenDays > 0 && o.PasswordResetTokenMinutes > 0,
                "Token lifetimes must be positive.")
            .ValidateOnStart();

        // Authentication: ¿quién sos? → JwtBearer valida el access token de cada request.
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
        services.AddSingleton<IConfigureOptions<JwtBearerOptions>, JwtBearerSetup>();

        // Authorization: ¿qué tenés permitido hacer?
        services.AddAuthorization();
        services.AddSingleton<IAuthorizationHandler, PermissionAuthorizationHandler>();

        // Rate limiting de /auth/*: frena ataques de fuerza bruta contra login, reset, etc.
        services.AddRateLimiter(limiter =>
        {
            limiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            limiter.AddPolicy(AuthRateLimitPolicy, http => RateLimitPartition.GetFixedWindowLimiter(
                partitionKey: http.Connection.RemoteIpAddress?.ToString() ?? "unknown", // un contador por IP
                factory: _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = http.RequestServices.GetRequiredService<IOptions<AuthOptions>>().Value.AuthRateLimitPerMinute,
                    Window = TimeSpan.FromMinutes(1)
                }));
        });

        services.AddSingleton<IPasswordHasher, BcryptPasswordHasher>();
        services.AddSingleton<JwtTokenService>();
        services.AddScoped<RefreshTokenService>();
        services.AddScoped<PasswordResetService>();
        services.AddScoped<UserService>();
        services.AddScoped<AuthService>();

        return services;
    }
}

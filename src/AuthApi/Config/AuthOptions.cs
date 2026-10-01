namespace AuthApi.Config;

/// <summary>
/// Configuración del módulo de autenticación.
/// Todos los valores salen de variables de entorno (o de un archivo .env en desarrollo);
/// ningún secreto está escrito en el código.
/// </summary>
public sealed class AuthOptions
{
    /// <summary>Clave HMAC con la que se firman los JWT. Mínimo 32 caracteres (256 bits).</summary>
    public string JwtSecret { get; set; } = "";
    public string JwtIssuer { get; set; } = "auth-api";
    public string JwtAudience { get; set; } = "auth-api-clients";

    /// <summary>Vida del access token. Corta a propósito: si se filtra, sirve poco tiempo.</summary>
    public int AccessTokenMinutes { get; set; } = 15;

    /// <summary>Vida del refresh token. Más larga: evita pedir la contraseña constantemente.</summary>
    public int RefreshTokenDays { get; set; } = 7;

    public int PasswordResetTokenMinutes { get; set; } = 15;

    /// <summary>
    /// SOLO para demo/desarrollo: devuelve el token de recuperación en la respuesta
    /// en lugar de enviarlo por email. Nunca activarlo en producción.
    /// </summary>
    public bool ExposePasswordResetToken { get; set; }

    /// <summary>Costo de BCrypt (2^n iteraciones). Más alto = más lento para un atacante.</summary>
    public int BcryptWorkFactor { get; set; } = 12;

    /// <summary>Intentos permitidos por minuto y por IP en los endpoints /auth.</summary>
    public int AuthRateLimitPerMinute { get; set; } = 10;

    /// <summary>Lee la configuración usando los nombres de variables de entorno documentados en .env.example.</summary>
    public void Load(IConfiguration config)
    {
        JwtSecret = config["JWT_SECRET"] ?? JwtSecret;
        JwtIssuer = config["JWT_ISSUER"] ?? JwtIssuer;
        JwtAudience = config["JWT_AUDIENCE"] ?? JwtAudience;
        AccessTokenMinutes = config.GetValue("JWT_ACCESS_TOKEN_MINUTES", AccessTokenMinutes);
        RefreshTokenDays = config.GetValue("REFRESH_TOKEN_DAYS", RefreshTokenDays);
        PasswordResetTokenMinutes = config.GetValue("PASSWORD_RESET_TOKEN_MINUTES", PasswordResetTokenMinutes);
        ExposePasswordResetToken = config.GetValue("PASSWORD_RESET_EXPOSE_TOKEN", ExposePasswordResetToken);
        BcryptWorkFactor = config.GetValue("BCRYPT_WORK_FACTOR", BcryptWorkFactor);
        AuthRateLimitPerMinute = config.GetValue("AUTH_RATE_LIMIT_PER_MINUTE", AuthRateLimitPerMinute);
    }
}

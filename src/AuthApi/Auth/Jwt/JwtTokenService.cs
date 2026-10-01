using System.Security.Claims;
using System.Text;
using AuthApi.Config;
using AuthApi.Data.Entities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AuthApi.Auth.Jwt;

public sealed record AccessToken(string Token, DateTime ExpiresAt);

/// <summary>
/// Emite access tokens JWT y define cómo se validan.
///
/// Un JWT tiene tres partes en Base64Url separadas por puntos: header.payload.signature
/// - header:    algoritmo de firma ("alg": "HS256") y tipo ("typ": "JWT").
/// - payload:   claims (sub, role, exp, iss, aud…). Es LEGIBLE por cualquiera: está codificado, no cifrado.
/// - signature: HMAC-SHA256(header + "." + payload, JWT_SECRET). Prueba que el token lo emitió
///              este servidor y que nadie modificó el payload.
/// </summary>
public sealed class JwtTokenService(IOptions<AuthOptions> options, TimeProvider time)
{
    public const string RoleClaim = "role";

    private readonly AuthOptions _options = options.Value;

    public AccessToken CreateAccessToken(User user)
    {
        var now = time.GetUtcNow().UtcDateTime;
        var expiresAt = now.AddMinutes(_options.AccessTokenMinutes);

        // Payload mínimo: identidad (sub) y rol. Nada sensible: ni contraseña, ni hash,
        // ni datos personales innecesarios, porque cualquiera que tenga el token puede leerlo.
        var claims = new ClaimsIdentity(
        [
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // id único del token
            new Claim(RoleClaim, user.Role)
        ]);

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = claims,
            Issuer = _options.JwtIssuer,
            Audience = _options.JwtAudience,
            IssuedAt = now,
            NotBefore = now,
            Expires = expiresAt,
            SigningCredentials = new SigningCredentials(CreateSigningKey(_options), SecurityAlgorithms.HmacSha256)
        };

        return new AccessToken(new JsonWebTokenHandler().CreateToken(descriptor), expiresAt);
    }

    /// <summary>
    /// Reglas de validación que aplica el middleware JwtBearer en cada request protegido.
    /// </summary>
    public static TokenValidationParameters CreateValidationParameters(AuthOptions options) => new()
    {
        ValidateIssuerSigningKey = true,                 // la firma debe corresponder a JWT_SECRET
        IssuerSigningKey = CreateSigningKey(options),
        ValidAlgorithms = [SecurityAlgorithms.HmacSha256], // rechaza "alg": "none" u otros algoritmos
        ValidateIssuer = true,
        ValidIssuer = options.JwtIssuer,
        ValidateAudience = true,
        ValidAudience = options.JwtAudience,
        ValidateLifetime = true,                         // rechaza tokens expirados (exp) o aún no válidos (nbf)
        RequireExpirationTime = true,
        ClockSkew = TimeSpan.FromSeconds(30),            // tolerancia por diferencias de reloj entre servidores
        NameClaimType = JwtRegisteredClaimNames.Sub,
        RoleClaimType = RoleClaim
    };

    private static SymmetricSecurityKey CreateSigningKey(AuthOptions options) =>
        new(Encoding.UTF8.GetBytes(options.JwtSecret));
}

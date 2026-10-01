using AuthApi.Config;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthApi.Auth.Jwt;

/// <summary>
/// Configura el middleware de AUTENTICACIÓN (JwtBearer). En cada request:
///   1. Lee el header "Authorization: Bearer &lt;token&gt;".
///   2. Valida formato, firma, algoritmo, issuer, audience y expiración (ver CreateValidationParameters).
///   3. Si es válido, construye HttpContext.User con los claims del token (la identidad).
///   4. Si un endpoint requiere autenticación y no hay identidad válida → 401 (OnChallenge).
///   5. Si hay identidad pero la AUTORIZACIÓN falla (falta un permiso) → 403 (OnForbidden).
/// </summary>
public sealed class JwtBearerSetup(IOptions<AuthOptions> authOptions) : IConfigureNamedOptions<JwtBearerOptions>
{
    public void Configure(string? name, JwtBearerOptions options)
    {
        // Mantiene los nombres de claims del JWT ("sub", "role") en vez de mapearlos a URIs largas de .NET.
        options.MapInboundClaims = false;
        options.TokenValidationParameters = JwtTokenService.CreateValidationParameters(authOptions.Value);

        options.Events = new JwtBearerEvents
        {
            OnChallenge = async context =>
            {
                context.HandleResponse(); // reemplaza la respuesta 401 vacía por defecto
                var expired = context.AuthenticateFailure is SecurityTokenExpiredException;
                var detail = context.AuthenticateFailure switch
                {
                    null => "An access token is required.",
                    SecurityTokenExpiredException => "The access token has expired.",
                    _ => "The access token is invalid."
                };

                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.Headers.WWWAuthenticate = context.AuthenticateFailure is null
                    ? "Bearer"
                    : $"Bearer error=\"invalid_token\", error_description=\"{(expired ? "expired" : "invalid")}\"";
                await WriteProblemAsync(context.HttpContext, StatusCodes.Status401Unauthorized, "Unauthorized", detail);
            },
            OnForbidden = context =>
                WriteProblemAsync(context.HttpContext, StatusCodes.Status403Forbidden, "Forbidden",
                    "You do not have permission to perform this action.")
        };
    }

    public void Configure(JwtBearerOptions options) => Configure(Options.DefaultName, options);

    private static async Task WriteProblemAsync(HttpContext http, int status, string title, string detail)
    {
        http.Response.StatusCode = status;
        var problems = http.RequestServices.GetRequiredService<IProblemDetailsService>();
        await problems.WriteAsync(new ProblemDetailsContext
        {
            HttpContext = http,
            ProblemDetails = new ProblemDetails { Status = status, Title = title, Detail = detail }
        });
    }
}

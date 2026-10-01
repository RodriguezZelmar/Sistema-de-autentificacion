using AuthApi.Config;
using AuthApi.Users;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace AuthApi.Auth;

/// <summary>
/// Endpoints públicos de autenticación. El controller solo traduce HTTP ↔ service:
/// la validación de entrada la hace [ApiController] (devuelve 400 automáticamente) y la lógica vive en AuthService.
/// </summary>
[ApiController]
[Route("auth")]
[EnableRateLimiting(AuthModuleExtensions.AuthRateLimitPolicy)]
[ProducesResponseType(StatusCodes.Status429TooManyRequests)]
public sealed class AuthController(AuthService auth) : ControllerBase
{
    /// <summary>Registra un usuario nuevo con rol USER.</summary>
    [HttpPost("register")]
    [ProducesResponseType<UserResponse>(StatusCodes.Status201Created)]
    [ProducesResponseType<ValidationProblemDetails>(StatusCodes.Status400BadRequest)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Register(RegisterRequest request, CancellationToken ct)
    {
        var user = await auth.RegisterAsync(request, ct);
        return Created($"/users/{user.Id}", user);
    }

    /// <summary>Inicia sesión y devuelve las credenciales para usar la API.</summary>
    [HttpPost("login")]
    [ProducesResponseType<TokenResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status403Forbidden)]
    public async Task<TokenResponse> Login(LoginRequest request, CancellationToken ct) =>
        await auth.LoginAsync(request, ct);

    /// <summary>Obtiene un access token nuevo usando el refresh token (que se rota: el anterior deja de servir).</summary>
    [HttpPost("refresh")]
    [ProducesResponseType<TokenResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status401Unauthorized)]
    public async Task<TokenResponse> Refresh(RefreshTokenRequest request, CancellationToken ct) =>
        await auth.RefreshAsync(request, ct);

    /// <summary>
    /// Revoca el refresh token. No exige access token: poseer el refresh token alcanza,
    /// y así se puede cerrar sesión aunque el access token ya haya expirado.
    /// Siempre responde 204 (idempotente, y no revela si el token existía).
    /// </summary>
    [HttpPost("logout")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Logout(RefreshTokenRequest request, CancellationToken ct)
    {
        await auth.LogoutAsync(request, ct);
        return NoContent();
    }

    /// <summary>
    /// Inicia la recuperación de contraseña (SIMULADA: no se envía email).
    /// Responde siempre 200 con el mismo mensaje, exista o no el email.
    /// </summary>
    [HttpPost("forgot-password")]
    [ProducesResponseType<ForgotPasswordResponse>(StatusCodes.Status200OK)]
    public async Task<ForgotPasswordResponse> ForgotPassword(ForgotPasswordRequest request, CancellationToken ct) =>
        await auth.ForgotPasswordAsync(request, ct);

    /// <summary>Cambia la contraseña usando el token de recuperación (válido una sola vez).</summary>
    [HttpPost("reset-password")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ResetPassword(ResetPasswordRequest request, CancellationToken ct)
    {
        await auth.ResetPasswordAsync(request, ct);
        return NoContent();
    }
}

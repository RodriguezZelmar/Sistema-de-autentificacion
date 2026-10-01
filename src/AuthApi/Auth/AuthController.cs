using AuthApi.Users;
using Microsoft.AspNetCore.Mvc;

namespace AuthApi.Auth;

/// <summary>
/// Endpoints públicos de autenticación. El controller solo traduce HTTP ↔ service:
/// la validación de entrada la hace [ApiController] (devuelve 400 automáticamente) y la lógica vive en AuthService.
/// </summary>
[ApiController]
[Route("auth")]
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
}

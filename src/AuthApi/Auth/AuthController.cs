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
}

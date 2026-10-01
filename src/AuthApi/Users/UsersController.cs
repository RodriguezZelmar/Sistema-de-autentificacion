using AuthApi.Auth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthApi.Users;

/// <summary>
/// Recurso de DEMOSTRACIÓN. Existe solo para mostrar autenticación y autorización en acción.
/// </summary>
[ApiController]
[Route("users")]
public sealed class UsersController(UserService users) : ControllerBase
{
    /// <summary>
    /// Perfil del usuario autenticado. Solo requiere AUTENTICACIÓN (un access token válido):
    /// cualquier usuario logueado puede ver su propio perfil, sin importar su rol.
    /// </summary>
    [HttpGet("me")]
    [Authorize]
    [ProducesResponseType<UserResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status401Unauthorized)]
    public async Task<UserResponse> Me(CancellationToken ct) =>
        UserResponse.From(await users.GetByIdAsync(User.GetUserId(), ct));
}

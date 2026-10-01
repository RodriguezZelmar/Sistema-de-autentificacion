using AuthApi.Auth;
using AuthApi.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthApi.Users;

/// <summary>
/// Recurso de DEMOSTRACIÓN. Existe solo para mostrar autenticación y autorización en acción:
/// - [Authorize]                      → solo autenticación (¿quién sos?)
/// - [RequirePermission("users:...")] → autenticación + autorización (¿qué podés hacer?)
/// </summary>
[ApiController]
[Route("users")]
[ProducesResponseType<ProblemDetails>(StatusCodes.Status401Unauthorized)]
public sealed class UsersController(UserService users) : ControllerBase
{
    /// <summary>
    /// Perfil del usuario autenticado y sus permisos. Solo requiere AUTENTICACIÓN (un access token válido):
    /// cualquier usuario logueado puede ver su propio perfil, sin importar su rol.
    /// </summary>
    [HttpGet("me")]
    [Authorize]
    [ProducesResponseType<CurrentUserResponse>(StatusCodes.Status200OK)]
    public async Task<CurrentUserResponse> Me(CancellationToken ct)
    {
        var user = await users.GetByIdAsync(User.GetUserId(), ct);
        return new CurrentUserResponse(UserResponse.From(user), RolePermissions.For(user.Role).Order().ToList());
    }

    /// <summary>Lista usuarios. Requiere el permiso users:read (USER y ADMIN lo tienen).</summary>
    [HttpGet]
    [RequirePermission(Permissions.UsersRead)]
    [ProducesResponseType<List<UserResponse>>(StatusCodes.Status200OK)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status403Forbidden)]
    public async Task<IEnumerable<UserResponse>> List(CancellationToken ct) =>
        (await users.ListAsync(ct)).Select(UserResponse.From);
}

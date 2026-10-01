using AuthApi.Authorization;
using AuthApi.Users;

namespace AuthApi.Auth;

/// <summary>
/// Lógica de autenticación: registro, login, refresh, logout y recuperación de contraseña.
/// No conoce HTTP: recibe datos, devuelve resultados o lanza ApiException.
/// </summary>
public sealed class AuthService(UserService users, ILogger<AuthService> logger)
{
    public async Task<UserResponse> RegisterAsync(RegisterRequest request, CancellationToken ct)
    {
        // El registro público SIEMPRE crea usuarios con rol USER.
        var user = await users.CreateAsync(request.Email, request.Password, request.Name, Roles.User, ct);

        // Se registra el id, nunca la contraseña.
        logger.LogInformation("User {UserId} registered", user.Id);
        return UserResponse.From(user);
    }
}

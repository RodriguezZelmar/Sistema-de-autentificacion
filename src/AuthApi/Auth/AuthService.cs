using AuthApi.Auth.Jwt;
using AuthApi.Auth.Passwords;
using AuthApi.Authorization;
using AuthApi.Common;
using AuthApi.Data;
using AuthApi.Users;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Auth;

/// <summary>
/// Lógica de autenticación: registro, login, refresh, logout y recuperación de contraseña.
/// No conoce HTTP: recibe datos, devuelve resultados o lanza ApiException.
/// </summary>
public sealed class AuthService(
    AppDbContext db,
    UserService users,
    IPasswordHasher hasher,
    JwtTokenService jwt,
    TimeProvider time,
    ILogger<AuthService> logger)
{
    public async Task<UserResponse> RegisterAsync(RegisterRequest request, CancellationToken ct)
    {
        // El registro público SIEMPRE crea usuarios con rol USER.
        var user = await users.CreateAsync(request.Email, request.Password, request.Name, Roles.User, ct);

        // Se registra el id, nunca la contraseña.
        logger.LogInformation("User {UserId} registered", user.Id);
        return UserResponse.From(user);
    }

    public async Task<TokenResponse> LoginAsync(LoginRequest request, CancellationToken ct)
    {
        // 1. Buscar el usuario.
        var email = UserService.NormalizeEmail(request.Email);
        var user = await db.Users.SingleOrDefaultAsync(u => u.Email == email, ct);

        // 2. Comparar la contraseña con el hash. Si el usuario no existe se verifica igual contra un hash
        //    ficticio: misma demora y mismo mensaje en ambos casos → no se puede saber qué emails existen.
        var passwordOk = hasher.Verify(request.Password, user?.PasswordHash ?? hasher.DummyHash);
        if (user is null || !passwordOk)
        {
            logger.LogInformation("Failed login attempt");
            throw ApiException.Unauthorized("Invalid email or password.");
        }

        // 3. Verificar que el usuario pueda iniciar sesión.
        if (!user.IsActive)
            throw ApiException.Forbidden("This account is disabled.");

        // 4. Emitir credenciales.
        var accessToken = jwt.CreateAccessToken(user);
        logger.LogInformation("User {UserId} logged in", user.Id);
        return ToTokenResponse(accessToken);
    }

    private TokenResponse ToTokenResponse(AccessToken accessToken) => new(
        accessToken.Token,
        "Bearer",
        (int)(accessToken.ExpiresAt - time.GetUtcNow().UtcDateTime).TotalSeconds,
        accessToken.ExpiresAt);
}

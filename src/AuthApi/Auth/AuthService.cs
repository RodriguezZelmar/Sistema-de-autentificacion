using AuthApi.Auth.Jwt;
using AuthApi.Auth.Passwords;
using AuthApi.Auth.Tokens;
using AuthApi.Authorization;
using AuthApi.Common;
using AuthApi.Config;
using AuthApi.Data;
using AuthApi.Users;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

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
    RefreshTokenService refreshTokens,
    PasswordResetService passwordResets,
    IOptions<AuthOptions> options,
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

        // 4. Emitir credenciales: access token (corto, stateless) + refresh token (largo, guardado en la base).
        var refreshToken = await refreshTokens.IssueAsync(user, ct);
        logger.LogInformation("User {UserId} logged in", user.Id);
        return ToTokenResponse(jwt.CreateAccessToken(user), refreshToken);
    }

    /// <summary>
    /// Canjea un refresh token válido por credenciales nuevas, sin volver a pedir la contraseña.
    /// El refresh token usado queda revocado (rotación).
    /// </summary>
    public async Task<TokenResponse> RefreshAsync(RefreshTokenRequest request, CancellationToken ct)
    {
        var (user, newRefreshToken) = await refreshTokens.RotateAsync(request.RefreshToken, ct);

        // El access token nuevo se genera con los datos ACTUALES del usuario (p. ej. si cambió su rol).
        return ToTokenResponse(jwt.CreateAccessToken(user), newRefreshToken);
    }

    /// <summary>
    /// Logout: revoca el refresh token → la sesión ya no puede renovarse.
    /// El access token ya emitido sigue siendo válido hasta que expire (máx. 15 min), porque un JWT es stateless.
    /// </summary>
    public Task LogoutAsync(RefreshTokenRequest request, CancellationToken ct) =>
        refreshTokens.RevokeAsync(request.RefreshToken, ct);

    public async Task<ForgotPasswordResponse> ForgotPasswordAsync(ForgotPasswordRequest request, CancellationToken ct)
    {
        const string message = "If the email is registered, password reset instructions have been sent.";
        var issued = await passwordResets.RequestAsync(request.Email, ct);

        // SIMPLIFICACIÓN EDUCATIVA: en modo demo se devuelve el token para poder probar el flujo sin email.
        // En producción (PASSWORD_RESET_EXPOSE_TOKEN=false) la respuesta es idéntica exista o no el usuario.
        return issued is not null && options.Value.ExposePasswordResetToken
            ? new ForgotPasswordResponse(message, issued.Token, issued.ExpiresAt)
            : new ForgotPasswordResponse(message);
    }

    public Task ResetPasswordAsync(ResetPasswordRequest request, CancellationToken ct) =>
        passwordResets.ResetAsync(request.Token, request.NewPassword, ct);

    private TokenResponse ToTokenResponse(AccessToken accessToken, IssuedRefreshToken refreshToken) => new(
        accessToken.Token,
        "Bearer",
        (int)(accessToken.ExpiresAt - time.GetUtcNow().UtcDateTime).TotalSeconds,
        accessToken.ExpiresAt,
        refreshToken.Token,
        refreshToken.ExpiresAt);
}

using System.ComponentModel.DataAnnotations;
using AuthApi.Auth.Validation;

namespace AuthApi.Auth;

// Los DTOs de entrada NO tienen propiedad "Role": si un cliente envía {"role":"ADMIN"}
// al registrarse, el campo simplemente se ignora. El rol lo decide el servidor.

public sealed record RegisterRequest(
    [Required, EmailAddress, MaxLength(254)] string Email,
    [Required, PasswordPolicy] string Password,
    [MaxLength(100)] string? Name);

public sealed record LoginRequest(
    [Required, EmailAddress, MaxLength(254)] string Email,
    [Required, MaxLength(200)] string Password);

/// <summary>Usado por /auth/refresh y /auth/logout.</summary>
public sealed record RefreshTokenRequest(
    [Required, MaxLength(200)] string RefreshToken);

/// <summary>Credenciales devueltas por login y refresh. Formato inspirado en OAuth 2.0.</summary>
public sealed record TokenResponse(
    string AccessToken,
    string TokenType,
    int ExpiresIn,              // segundos de vida del access token
    DateTime AccessTokenExpiresAt,
    string RefreshToken,
    DateTime RefreshTokenExpiresAt);

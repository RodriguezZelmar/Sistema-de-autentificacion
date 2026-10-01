using System.ComponentModel.DataAnnotations;

namespace AuthApi.Auth.Validation;

/// <summary>
/// Política de contraseñas: entre 8 y 72 caracteres, con al menos una letra y un número.
/// El máximo existe porque BCrypt solo usa los primeros 72 bytes: sin límite, dos contraseñas
/// largas que compartan esos 72 bytes serían equivalentes. También evita payloads gigantes.
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Parameter)]
public sealed class PasswordPolicyAttribute : ValidationAttribute
{
    public const int MinLength = 8;
    public const int MaxLength = 72;

    public PasswordPolicyAttribute()
        : base($"Password must be {MinLength}-{MaxLength} characters long and contain at least one letter and one number.")
    {
    }

    public override bool IsValid(object? value) =>
        value is string password
        && password.Length is >= MinLength and <= MaxLength
        && password.Any(char.IsLetter)
        && password.Any(char.IsDigit);
}

using AuthApi.Config;
using Microsoft.Extensions.Options;

namespace AuthApi.Auth.Passwords;

/// <summary>
/// BCrypt es adecuado para contraseñas (a diferencia de SHA-256 o MD5) porque:
/// - es lento a propósito y su costo es configurable (work factor), lo que encarece los ataques de fuerza bruta;
/// - genera un salt aleatorio por contraseña, así dos usuarios con la misma contraseña tienen hashes distintos
///   y las rainbow tables no sirven.
/// El hash resultante ("$2a$12$...") incluye algoritmo, costo y salt, por eso no hace falta guardarlos aparte.
/// </summary>
public sealed class BcryptPasswordHasher(IOptions<AuthOptions> options) : IPasswordHasher
{
    private readonly int _workFactor = options.Value.BcryptWorkFactor;

    public string Hash(string password) => BCrypt.Net.BCrypt.HashPassword(password, _workFactor);

    // Verify recalcula el hash con el salt guardado y compara en tiempo constante.
    public bool Verify(string password, string passwordHash) => BCrypt.Net.BCrypt.Verify(password, passwordHash);
}

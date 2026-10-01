namespace AuthApi.Auth.Passwords;

/// <summary>
/// Abstracción del algoritmo de hashing. El resto del código no sabe que se usa BCrypt:
/// cambiar a Argon2 o PBKDF2 sería implementar esta interfaz.
/// </summary>
public interface IPasswordHasher
{
    string Hash(string password);
    bool Verify(string password, string passwordHash);

    /// <summary>
    /// Hash válido de una contraseña aleatoria. El login lo verifica cuando el email no existe,
    /// para tardar lo mismo que con un usuario real y no revelar qué emails están registrados (timing attack).
    /// </summary>
    string DummyHash { get; }
}

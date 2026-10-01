namespace AuthApi.Auth.Passwords;

/// <summary>
/// Abstracción del algoritmo de hashing. El resto del código no sabe que se usa BCrypt:
/// cambiar a Argon2 o PBKDF2 sería implementar esta interfaz.
/// </summary>
public interface IPasswordHasher
{
    string Hash(string password);
    bool Verify(string password, string passwordHash);
}

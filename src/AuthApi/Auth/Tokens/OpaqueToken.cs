using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace AuthApi.Auth.Tokens;

/// <summary>
/// Tokens "opacos" (strings aleatorios sin significado) usados para refresh y recuperación de contraseña.
/// A diferencia del JWT, no contienen datos: el servidor los busca en la base de datos.
/// </summary>
public static class OpaqueToken
{
    /// <summary>64 bytes (512 bits) de un generador criptográficamente seguro, en Base64Url.</summary>
    public static string Generate() => Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(64));

    /// <summary>
    /// SHA-256 del token: es lo único que se guarda en la base. Si la base se filtra, los hashes no sirven
    /// para usar la API. SHA-256 (rápido) es suficiente acá —a diferencia de las contraseñas— porque el token
    /// tiene 512 bits aleatorios: es imposible de adivinar por fuerza bruta. Además, al ser determinístico,
    /// permite buscar el token por un índice en la base.
    /// </summary>
    public static string Hash(string token) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
}

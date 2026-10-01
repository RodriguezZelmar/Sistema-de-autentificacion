using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;

namespace AuthApi.Auth;

public static class ClaimsPrincipalExtensions
{
    /// <summary>Id del usuario autenticado, tomado del claim "sub" del access token ya validado.</summary>
    public static Guid GetUserId(this ClaimsPrincipal principal) =>
        Guid.Parse(principal.FindFirstValue(JwtRegisteredClaimNames.Sub)
                   ?? throw new InvalidOperationException("Authenticated principal has no 'sub' claim."));
}

namespace AuthApi.Authorization;

/// <summary>
/// Roles del sistema. Se guardan como string en la base y viajan en el claim "role" del JWT.
/// </summary>
public static class Roles
{
    public const string User = "USER";
    public const string Admin = "ADMIN";

    public static readonly IReadOnlySet<string> All = new HashSet<string> { User, Admin };
}

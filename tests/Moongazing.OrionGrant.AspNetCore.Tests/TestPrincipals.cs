namespace Moongazing.OrionGrant.AspNetCore.Tests;

using System.Security.Claims;

/// <summary>
/// Helpers for building authenticated <see cref="ClaimsPrincipal"/> instances carrying OrionGrant
/// grants in the claim types the default <see cref="ClaimsGrantPrincipalResolver"/> reads.
/// </summary>
internal static class TestPrincipals
{
    public const string AuthenticationType = "Test";

    public static ClaimsPrincipal With(
        string subject,
        IEnumerable<string>? permissions = null,
        IEnumerable<string>? roles = null,
        IEnumerable<string>? denies = null)
    {
        var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, subject) };

        foreach (var permission in permissions ?? [])
        {
            claims.Add(new Claim("permission", permission));
        }

        foreach (var role in roles ?? [])
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        foreach (var deny in denies ?? [])
        {
            claims.Add(new Claim("deny", deny));
        }

        return new ClaimsPrincipal(new ClaimsIdentity(claims, AuthenticationType));
    }

    public static ClaimsPrincipal Anonymous() => new(new ClaimsIdentity());
}

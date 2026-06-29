namespace Moongazing.OrionGrant.AspNetCore;

using System.Security.Claims;

/// <summary>
/// Configures which claim types the default <see cref="ClaimsGrantPrincipalResolver"/> reads when
/// building a <see cref="GrantPrincipal"/> from a <see cref="ClaimsPrincipal"/>. Defaults match the
/// conventional ASP.NET Core claim types; override any of them to match the tokens an application
/// actually issues.
/// </summary>
public sealed class OrionGrantClaimsOptions
{
    /// <summary>
    /// The claim type carrying the subject identity used as <see cref="GrantPrincipal.Subject"/>.
    /// The first matching claim is used. Defaults to <see cref="ClaimTypes.NameIdentifier"/>; the
    /// JWT-style <c>sub</c> claim is also consulted as a fallback when this claim is absent.
    /// </summary>
    public string SubjectClaimType { get; set; } = ClaimTypes.NameIdentifier;

    /// <summary>
    /// The claim type carrying role names. Each matching claim contributes one role. Defaults to
    /// <see cref="ClaimTypes.Role"/>.
    /// </summary>
    public string RoleClaimType { get; set; } = ClaimTypes.Role;

    /// <summary>
    /// The claim type carrying directly granted OrionGrant permissions. Each matching claim
    /// contributes one permission. Defaults to <c>permission</c>.
    /// </summary>
    public string PermissionClaimType { get; set; } = "permission";

    /// <summary>
    /// The claim type carrying explicit OrionGrant deny patterns. Each matching claim contributes
    /// one deny entry. Defaults to <c>deny</c>.
    /// </summary>
    public string DenyClaimType { get; set; } = "deny";

    /// <summary>
    /// The validation message produced when one of the configured claim types is null, empty, or
    /// whitespace. Used by <see cref="IsValid(OrionGrantClaimsOptions)"/> at registration.
    /// </summary>
    internal const string ValidationError =
        "OrionGrantClaimsOptions requires non-empty SubjectClaimType, RoleClaimType, " +
        "PermissionClaimType, and DenyClaimType: an empty claim type would silently read no claims.";

    /// <summary>
    /// True when every configured claim type is non-empty. An empty claim type is rejected at startup
    /// because <see cref="ClaimsPrincipal.FindAll(string)"/> against an empty type silently matches
    /// nothing, turning a typo into an unauthenticated principal rather than a clear failure.
    /// </summary>
    /// <param name="options">The options to validate.</param>
    internal static bool IsValid(OrionGrantClaimsOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return !string.IsNullOrWhiteSpace(options.SubjectClaimType)
            && !string.IsNullOrWhiteSpace(options.RoleClaimType)
            && !string.IsNullOrWhiteSpace(options.PermissionClaimType)
            && !string.IsNullOrWhiteSpace(options.DenyClaimType);
    }
}

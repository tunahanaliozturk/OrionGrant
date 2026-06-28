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
}

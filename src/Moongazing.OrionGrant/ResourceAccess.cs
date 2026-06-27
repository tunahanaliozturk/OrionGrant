namespace Moongazing.OrionGrant;

using Moongazing.OrionGrant.Permissions;

/// <summary>
/// Shared ownership and elevation rules for resource-aware authorization, factored out so the
/// <see cref="IGrantAuthorizer"/> default interface method and the concrete
/// <see cref="GrantAuthorizer"/> apply identical semantics.
/// </summary>
internal static class ResourceAccess
{
    private const string RootWildcard = "*";

    /// <summary>
    /// Does the principal own the resource? True when the resource has a non-empty owner id that
    /// equals the principal subject under the configured comparison.
    /// </summary>
    internal static bool IsOwner(
        GrantPrincipal principal,
        ResourceContext resource,
        ResourceAuthorizationOptions options)
    {
        if (string.IsNullOrEmpty(resource.OwnerId))
        {
            return false;
        }

        return string.Equals(principal.Subject, resource.OwnerId, options.OwnerComparison);
    }

    /// <summary>
    /// Does the principal's effective grant set carry an elevated grant that bypasses ownership?
    /// True when a root <c>*</c> is held and treated as elevated, or when any configured elevated
    /// permission is granted by the allow set. The deny-overrides rule applies here too: an elevated
    /// grant that is itself covered by an explicit deny does not elevate, so a matching deny strips
    /// the bypass and ownership governs again. This keeps deny precedence uniform across the elevated
    /// path and the ordinary permission path.
    /// </summary>
    /// <param name="grants">The principal's resolved allow and deny set.</param>
    /// <param name="options">The resource authorization options.</param>
    internal static bool IsElevated(EffectiveGrantSet grants, ResourceAuthorizationOptions options)
    {
        if (options.TreatRootWildcardAsElevated
            && grants.Allows.Contains(RootWildcard)
            && grants.MatchingDeny(RootWildcard) is null)
        {
            return true;
        }

        foreach (var elevated in options.ElevatedPermissions)
        {
            if (!string.IsNullOrEmpty(elevated)
                && PermissionMatcher.IsGrantedByAny(grants.Allows, elevated)
                && grants.MatchingDeny(elevated) is null)
            {
                return true;
            }
        }

        return false;
    }
}

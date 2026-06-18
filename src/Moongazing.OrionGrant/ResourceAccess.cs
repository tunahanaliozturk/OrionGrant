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
    /// Does the principal's effective permission set carry an elevated grant that bypasses
    /// ownership? True when a root <c>*</c> is held and treated as elevated, or when any configured
    /// elevated permission is granted by the effective set.
    /// </summary>
    internal static bool IsElevated(IReadOnlySet<string> effective, ResourceAuthorizationOptions options)
    {
        if (options.TreatRootWildcardAsElevated && effective.Contains(RootWildcard))
        {
            return true;
        }

        foreach (var elevated in options.ElevatedPermissions)
        {
            if (!string.IsNullOrEmpty(elevated) && PermissionMatcher.IsGrantedByAny(effective, elevated))
            {
                return true;
            }
        }

        return false;
    }
}

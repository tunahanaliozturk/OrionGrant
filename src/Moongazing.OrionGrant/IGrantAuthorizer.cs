namespace Moongazing.OrionGrant;

/// <summary>
/// Evaluates whether a principal is authorized, either for a single permission or for a named
/// policy. Roles are expanded into permissions and unioned with the principal's direct grants.
/// </summary>
public interface IGrantAuthorizer
{
    /// <summary>Authorize a principal for a single required permission.</summary>
    /// <param name="principal">The subject of the decision.</param>
    /// <param name="requiredPermission">The permission required.</param>
    AuthorizationResult Authorize(GrantPrincipal principal, string requiredPermission);

    /// <summary>
    /// Authorize a principal for a permission against a specific resource (object-level / ownership
    /// aware). The principal must both hold <paramref name="requiredPermission"/> and either own the
    /// resource described by <paramref name="resource"/> or hold an elevated grant that bypasses
    /// ownership. This is the IDOR-resistant path: holding <c>accounts:read</c> is necessary but not
    /// sufficient to read an account the principal does not own.
    /// </summary>
    /// <param name="principal">The subject of the decision.</param>
    /// <param name="requiredPermission">The permission required, in addition to ownership.</param>
    /// <param name="resource">The resource being accessed, including its owner identity.</param>
    /// <param name="options">
    /// Owner comparison and elevated-permission bypass configuration. Defaults to
    /// <see cref="ResourceAuthorizationOptions.Default"/> when null.
    /// </param>
    /// <remarks>
    /// Implemented as a default interface method so existing implementors keep compiling; the
    /// default delegates to <see cref="Authorize(GrantPrincipal, string)"/> and applies the
    /// ownership and elevation rules on top.
    /// </remarks>
    AuthorizationResult Authorize(
        GrantPrincipal principal,
        string requiredPermission,
        ResourceContext resource,
        ResourceAuthorizationOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentException.ThrowIfNullOrEmpty(requiredPermission);
        ArgumentNullException.ThrowIfNull(resource);

        var opts = options ?? ResourceAuthorizationOptions.Default;

        var permissionResult = Authorize(principal, requiredPermission);
        if (!permissionResult.IsGranted)
        {
            return permissionResult;
        }

        var effective = EffectivePermissions(principal);
        if (ResourceAccess.IsElevated(effective, opts))
        {
            return AuthorizationResult.Granted;
        }

        if (ResourceAccess.IsOwner(principal, resource, opts))
        {
            return AuthorizationResult.Granted;
        }

        return AuthorizationResult.Denied(
            $"Principal '{principal.Subject}' holds '{requiredPermission}' but is not the owner of " +
            $"the requested resource and holds no elevated grant.");
    }

    /// <summary>Authorize a principal against a named policy.</summary>
    /// <param name="principal">The subject of the decision.</param>
    /// <param name="policyName">The policy to evaluate.</param>
    AuthorizationResult AuthorizePolicy(GrantPrincipal principal, string policyName);

    /// <summary>
    /// The effective permission set for a principal: its direct permissions unioned with the
    /// permissions of every role it holds (unknown roles contribute nothing).
    /// </summary>
    /// <param name="principal">The subject.</param>
    IReadOnlySet<string> EffectivePermissions(GrantPrincipal principal);
}

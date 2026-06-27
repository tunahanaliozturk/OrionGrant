namespace Moongazing.OrionGrant;

using Moongazing.OrionGrant.Permissions;
using Moongazing.OrionGrant.Policies;

/// <summary>
/// Evaluates whether a principal is authorized, either for a single permission or for a named
/// policy. Roles are expanded into permissions and unioned with the principal's direct grants;
/// explicit denies on the principal override matching allows (deny-overrides), and a policy may
/// carry an attribute-based (ABAC) condition that is AND-composed with its permission requirement.
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

        // A deny on the required permission is already honored by the Authorize call above. The
        // interface contract exposes only the allow set (EffectivePermissions is allow-only), so the
        // default implementation evaluates elevation against an allow-only grant set. The concrete
        // GrantAuthorizer overrides this method to apply deny-overrides to the elevated grant itself.
        var effective = new EffectiveGrantSet(EffectivePermissions(principal));
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
            $"the requested resource and holds no elevated grant.",
            DenialReason.ResourceOwnership(requiredPermission, resource));
    }

    /// <summary>Authorize a principal against a named policy.</summary>
    /// <param name="principal">The subject of the decision.</param>
    /// <param name="policyName">The policy to evaluate.</param>
    AuthorizationResult AuthorizePolicy(GrantPrincipal principal, string policyName);

    /// <summary>
    /// Authorize a principal against a named policy, supplying attributes for the policy's optional
    /// attribute-based (ABAC) condition. The permission requirement is evaluated exactly as in
    /// <see cref="AuthorizePolicy(GrantPrincipal, string)"/>; if the policy carries a condition it is
    /// an additional AND gate evaluated against <paramref name="attributes"/>. A policy with no
    /// condition ignores the attributes and behaves identically to the two-argument overload.
    /// </summary>
    /// <param name="principal">The subject of the decision.</param>
    /// <param name="policyName">The policy to evaluate.</param>
    /// <param name="attributes">
    /// The principal, resource, and environment attributes the condition reads. Null synthesizes a
    /// context from the principal alone (no resource, no environment), which still satisfies
    /// conditions that read only the principal.
    /// </param>
    /// <remarks>
    /// Implemented as a default interface method so existing implementors keep compiling; the default
    /// ignores the attributes and delegates to <see cref="AuthorizePolicy(GrantPrincipal, string)"/>.
    /// The concrete <see cref="GrantAuthorizer"/> overrides it to evaluate the condition.
    /// </remarks>
    AuthorizationResult AuthorizePolicy(
        GrantPrincipal principal,
        string policyName,
        AuthorizationAttributes? attributes)
    {
        _ = attributes;
        return AuthorizePolicy(principal, policyName);
    }

    /// <summary>
    /// Authorize a principal for several required permissions in one call, returning a result per
    /// requirement in the order supplied. More efficient than calling
    /// <see cref="Authorize(GrantPrincipal, string)"/> in a loop: the implementation expands the
    /// principal's effective set once for the whole batch instead of once per permission.
    /// </summary>
    /// <param name="principal">The subject of the decision.</param>
    /// <param name="requiredPermissions">The permissions to check.</param>
    /// <returns>One <see cref="BatchAuthorizationResult"/> per requirement, in input order.</returns>
    /// <remarks>
    /// Implemented as a default interface method so existing implementors keep compiling; the
    /// default delegates to <see cref="Authorize(GrantPrincipal, string)"/> per item. The concrete
    /// <see cref="GrantAuthorizer"/> overrides it to share a single effective-set expansion.
    /// </remarks>
    IReadOnlyList<BatchAuthorizationResult> AuthorizeAll(
        GrantPrincipal principal,
        IReadOnlyCollection<string> requiredPermissions)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(requiredPermissions);

        var results = new List<BatchAuthorizationResult>(requiredPermissions.Count);
        foreach (var permission in requiredPermissions)
        {
            ArgumentException.ThrowIfNullOrEmpty(permission, nameof(requiredPermissions));
            results.Add(new BatchAuthorizationResult(permission, Authorize(principal, permission)));
        }

        return results;
    }

    /// <summary>
    /// Authorize a principal against several named policies in one call, returning a result per
    /// policy in the order supplied. More efficient than calling
    /// <see cref="AuthorizePolicy(GrantPrincipal, string)"/> in a loop for the same reason as
    /// <see cref="AuthorizeAll(GrantPrincipal, IReadOnlyCollection{string})"/>.
    /// </summary>
    /// <param name="principal">The subject of the decision.</param>
    /// <param name="policyNames">The policy names to evaluate.</param>
    /// <returns>One <see cref="BatchAuthorizationResult"/> per policy, in input order.</returns>
    /// <remarks>
    /// Implemented as a default interface method so existing implementors keep compiling; the
    /// default delegates to <see cref="AuthorizePolicy(GrantPrincipal, string)"/> per item.
    /// </remarks>
    IReadOnlyList<BatchAuthorizationResult> AuthorizeAllPolicies(
        GrantPrincipal principal,
        IReadOnlyCollection<string> policyNames)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(policyNames);

        var results = new List<BatchAuthorizationResult>(policyNames.Count);
        foreach (var policyName in policyNames)
        {
            ArgumentException.ThrowIfNullOrEmpty(policyName, nameof(policyNames));
            results.Add(new BatchAuthorizationResult(policyName, AuthorizePolicy(principal, policyName)));
        }

        return results;
    }

    /// <summary>
    /// Authorize a principal against several named policies in one call, supplying attributes for any
    /// policy that carries an attribute-based (ABAC) condition. The same attributes are applied to
    /// every policy in the batch. Returns one result per policy in input order.
    /// </summary>
    /// <param name="principal">The subject of the decision.</param>
    /// <param name="policyNames">The policy names to evaluate.</param>
    /// <param name="attributes">
    /// The attributes the conditions read. Null synthesizes a principal-only context. Policies with
    /// no condition ignore it.
    /// </param>
    /// <remarks>
    /// Implemented as a default interface method so existing implementors keep compiling; the default
    /// delegates per-item to <see cref="AuthorizePolicy(GrantPrincipal, string, AuthorizationAttributes?)"/>.
    /// The concrete <see cref="GrantAuthorizer"/> overrides it to share a single effective-set
    /// expansion across the batch.
    /// </remarks>
    IReadOnlyList<BatchAuthorizationResult> AuthorizeAllPolicies(
        GrantPrincipal principal,
        IReadOnlyCollection<string> policyNames,
        AuthorizationAttributes? attributes)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(policyNames);

        var results = new List<BatchAuthorizationResult>(policyNames.Count);
        foreach (var policyName in policyNames)
        {
            ArgumentException.ThrowIfNullOrEmpty(policyName, nameof(policyNames));
            results.Add(new BatchAuthorizationResult(
                policyName,
                AuthorizePolicy(principal, policyName, attributes)));
        }

        return results;
    }

    /// <summary>
    /// The effective permission set for a principal: its direct permissions unioned with the
    /// permissions of every role it holds (unknown roles contribute nothing). This is the allow set
    /// only; explicit denies are applied during authorization, not subtracted here, so an existing
    /// caller that reads this set sees the same value as in 0.3.0.
    /// </summary>
    /// <param name="principal">The subject.</param>
    IReadOnlySet<string> EffectivePermissions(GrantPrincipal principal);
}

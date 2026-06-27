namespace Moongazing.OrionGrant;

using Moongazing.OrionGrant.Diagnostics;
using Moongazing.OrionGrant.Permissions;
using Moongazing.OrionGrant.Policies;

/// <summary>
/// Default <see cref="IGrantAuthorizer"/>. Expands a principal's roles through the
/// <see cref="RoleRegistry"/>, unions them with its direct permissions, and matches against the
/// requirement using <see cref="PermissionMatcher"/> wildcard semantics. Explicit denies on the
/// principal override a matching allow (deny-overrides), and a policy's optional attribute-based
/// (ABAC) condition is AND-composed with its permission requirement.
/// </summary>
public sealed class GrantAuthorizer : IGrantAuthorizer
{
    private readonly RoleRegistry roles;
    private readonly PolicyRegistry policies;
    private readonly GrantDiagnostics diagnostics;
    private readonly IEffectiveGrantCache? cache;

    /// <summary>Create an authorizer.</summary>
    /// <param name="roles">The role registry.</param>
    /// <param name="policies">The policy registry.</param>
    /// <param name="diagnostics">The shared metrics instance.</param>
    public GrantAuthorizer(RoleRegistry roles, PolicyRegistry policies, GrantDiagnostics diagnostics)
        : this(roles, policies, diagnostics, cache: null)
    {
    }

    /// <summary>Create an authorizer with an optional effective-set cache.</summary>
    /// <param name="roles">The role registry.</param>
    /// <param name="policies">The policy registry.</param>
    /// <param name="diagnostics">The shared metrics instance.</param>
    /// <param name="cache">
    /// An optional cache of resolved effective grant sets, keyed on principal role/permission/deny
    /// membership. When null (the default), every call re-expands the set exactly as in 0.3.0. When
    /// supplied, repeated checks for the same principal membership reuse the cached set. The cache
    /// must be scoped to this authorizer's registry; see <see cref="IEffectiveGrantCache"/>.
    /// </param>
    public GrantAuthorizer(
        RoleRegistry roles,
        PolicyRegistry policies,
        GrantDiagnostics diagnostics,
        IEffectiveGrantCache? cache)
    {
        ArgumentNullException.ThrowIfNull(roles);
        ArgumentNullException.ThrowIfNull(policies);
        ArgumentNullException.ThrowIfNull(diagnostics);
        this.roles = roles;
        this.policies = policies;
        this.diagnostics = diagnostics;
        this.cache = cache;
    }

    /// <inheritdoc />
    public IReadOnlySet<string> EffectivePermissions(GrantPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        return EffectiveGrants(principal).Allows;
    }

    /// <summary>
    /// Resolve a principal's full effective grant set: its allow union (direct grants plus
    /// role-expanded grants) and its explicit denies. Served from the cache when one is configured
    /// and the principal's membership has been seen before, otherwise expanded and stored.
    /// </summary>
    /// <param name="principal">The subject.</param>
    private EffectiveGrantSet EffectiveGrants(GrantPrincipal principal)
    {
        return cache is null
            ? BuildEffectiveGrants(principal)
            : cache.GetOrAdd(principal, BuildEffectiveGrants);
    }

    private EffectiveGrantSet BuildEffectiveGrants(GrantPrincipal principal)
    {
        var allows = new HashSet<string>(principal.Permissions, StringComparer.Ordinal);
        foreach (var role in principal.Roles)
        {
            if (!string.IsNullOrEmpty(role))
            {
                allows.UnionWith(roles.PermissionsFor(role));
            }
        }

        if (principal.Denies.Count == 0)
        {
            return new EffectiveGrantSet(allows);
        }

        var denies = new HashSet<string>(StringComparer.Ordinal);
        foreach (var deny in principal.Denies)
        {
            if (!string.IsNullOrEmpty(deny))
            {
                denies.Add(deny);
            }
        }

        return new EffectiveGrantSet(allows, denies);
    }

    /// <inheritdoc />
    public AuthorizationResult Authorize(GrantPrincipal principal, string requiredPermission)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentException.ThrowIfNullOrEmpty(requiredPermission);

        var grants = EffectiveGrants(principal);
        return EvaluatePermission(grants, requiredPermission);
    }

    /// <inheritdoc />
    public AuthorizationResult Authorize(
        GrantPrincipal principal,
        string requiredPermission,
        ResourceContext resource,
        ResourceAuthorizationOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentException.ThrowIfNullOrEmpty(requiredPermission);
        ArgumentNullException.ThrowIfNull(resource);

        var opts = options ?? ResourceAuthorizationOptions.Default;
        var grants = EffectiveGrants(principal);

        // An explicit deny overrides everything, including ownership and elevation: a carve-out that
        // covers the permission removes it regardless of who owns the resource.
        var deny = grants.MatchingDeny(requiredPermission);
        if (deny is not null)
        {
            diagnostics.Record(granted: false, "resource");
            return AuthorizationResult.Denied(
                $"Permission '{requiredPermission}' is explicitly denied by '{deny}'.",
                DenialReason.ExplicitDeny(requiredPermission, deny));
        }

        // The base permission is a hard gate: without it, ownership is irrelevant (the IDOR fix).
        if (!PermissionMatcher.IsGrantedByAny(grants.Allows, requiredPermission))
        {
            diagnostics.Record(granted: false, "resource");
            return AuthorizationResult.Denied(
                $"Missing permission '{requiredPermission}'.",
                DenialReason.MissingPermission(requiredPermission));
        }

        // Owner OR elevated: an admin/root or a configured elevated grant bypasses ownership. The
        // elevated check honors deny-overrides, so an elevated grant that is itself explicitly denied
        // does not bypass ownership.
        var granted = ResourceAccess.IsElevated(grants, opts)
            || ResourceAccess.IsOwner(principal, resource, opts);

        diagnostics.Record(granted, "resource");
        return granted
            ? AuthorizationResult.Granted
            : AuthorizationResult.Denied(
                $"Principal '{principal.Subject}' holds '{requiredPermission}' but is not the owner of " +
                $"the requested resource and holds no elevated grant.",
                DenialReason.ResourceOwnership(requiredPermission, resource));
    }

    /// <inheritdoc />
    public AuthorizationResult AuthorizePolicy(GrantPrincipal principal, string policyName)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentException.ThrowIfNullOrEmpty(policyName);

        return AuthorizePolicy(principal, policyName, attributes: null);
    }

    /// <inheritdoc />
    public AuthorizationResult AuthorizePolicy(
        GrantPrincipal principal,
        string policyName,
        AuthorizationAttributes? attributes)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentException.ThrowIfNullOrEmpty(policyName);

        var policy = policies.Find(policyName);
        if (policy is null)
        {
            diagnostics.Record(granted: false, "policy");
            return AuthorizationResult.Denied(
                $"Unknown policy '{policyName}'.",
                DenialReason.PolicyNotFound(policyName));
        }

        var grants = EffectiveGrants(principal);
        return EvaluatePolicy(policy, grants, principal, attributes);
    }

    /// <inheritdoc />
    public IReadOnlyList<BatchAuthorizationResult> AuthorizeAll(
        GrantPrincipal principal,
        IReadOnlyCollection<string> requiredPermissions)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(requiredPermissions);

        // Expand the effective set once and reuse it for every requirement, rather than rebuilding
        // it per check as N separate Authorize calls would.
        var grants = EffectiveGrants(principal);
        var results = new List<BatchAuthorizationResult>(requiredPermissions.Count);
        foreach (var permission in requiredPermissions)
        {
            ArgumentException.ThrowIfNullOrEmpty(permission, nameof(requiredPermissions));
            results.Add(new BatchAuthorizationResult(permission, EvaluatePermission(grants, permission)));
        }

        return results;
    }

    /// <inheritdoc />
    public IReadOnlyList<BatchAuthorizationResult> AuthorizeAllPolicies(
        GrantPrincipal principal,
        IReadOnlyCollection<string> policyNames)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(policyNames);

        return AuthorizeAllPolicies(principal, policyNames, attributes: null);
    }

    /// <inheritdoc />
    public IReadOnlyList<BatchAuthorizationResult> AuthorizeAllPolicies(
        GrantPrincipal principal,
        IReadOnlyCollection<string> policyNames,
        AuthorizationAttributes? attributes)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(policyNames);

        // The effective set is the same for every policy, so build it once for the whole batch.
        var grants = EffectiveGrants(principal);
        var results = new List<BatchAuthorizationResult>(policyNames.Count);
        foreach (var policyName in policyNames)
        {
            ArgumentException.ThrowIfNullOrEmpty(policyName, nameof(policyNames));

            var policy = policies.Find(policyName);
            AuthorizationResult result;
            if (policy is null)
            {
                diagnostics.Record(granted: false, "policy");
                result = AuthorizationResult.Denied(
                    $"Unknown policy '{policyName}'.",
                    DenialReason.PolicyNotFound(policyName));
            }
            else
            {
                result = EvaluatePolicy(policy, grants, principal, attributes);
            }

            results.Add(new BatchAuthorizationResult(policyName, result));
        }

        return results;
    }

    /// <summary>
    /// Evaluate one permission against an already-resolved effective grant set, recording the
    /// decision. A matching explicit deny overrides any allow (deny-overrides). Shared by the
    /// single-permission and batch paths so both apply identical semantics.
    /// </summary>
    private AuthorizationResult EvaluatePermission(EffectiveGrantSet grants, string requiredPermission)
    {
        var deny = grants.MatchingDeny(requiredPermission);
        if (deny is not null)
        {
            diagnostics.Record(granted: false, "permission");
            return AuthorizationResult.Denied(
                $"Permission '{requiredPermission}' is explicitly denied by '{deny}'.",
                DenialReason.ExplicitDeny(requiredPermission, deny));
        }

        var granted = PermissionMatcher.IsGrantedByAny(grants.Allows, requiredPermission);
        diagnostics.Record(granted, "permission");
        return granted
            ? AuthorizationResult.Granted
            : AuthorizationResult.Denied(
                $"Missing permission '{requiredPermission}'.",
                DenialReason.MissingPermission(requiredPermission));
    }

    /// <summary>
    /// Evaluate one policy against an already-resolved effective grant set, recording the decision.
    /// Applies the permission requirement first (honoring denies), then the policy's optional ABAC
    /// condition. Shared by the single-policy and batch paths.
    /// </summary>
    private AuthorizationResult EvaluatePolicy(
        AccessPolicy policy,
        EffectiveGrantSet grants,
        GrantPrincipal principal,
        AuthorizationAttributes? attributes)
    {
        var result = Evaluate(policy, grants, principal, attributes);
        diagnostics.Record(result.IsGranted, "policy");
        return result;
    }

    private static AuthorizationResult Evaluate(
        AccessPolicy policy,
        EffectiveGrantSet grants,
        GrantPrincipal principal,
        AuthorizationAttributes? attributes)
    {
        var permissionResult = EvaluatePolicyPermissions(policy, grants);
        if (!permissionResult.IsGranted)
        {
            return permissionResult;
        }

        // The permission requirement passed. If the policy carries an ABAC condition, it is an
        // additional AND gate evaluated against the supplied attributes (or an attributes context
        // synthesized from the principal when the caller passed none).
        if (policy.Condition is { } condition)
        {
            var context = attributes ?? AuthorizationAttributes.For(principal);
            if (!condition(context))
            {
                return AuthorizationResult.Denied(
                    $"Policy '{policy.Name}' condition was not satisfied.",
                    DenialReason.ConditionUnmet(policy.Name));
            }
        }

        return AuthorizationResult.Granted;
    }

    private static AuthorizationResult EvaluatePolicyPermissions(AccessPolicy policy, EffectiveGrantSet grants)
    {
        if (policy.Mode == PolicyMode.RequireAny)
        {
            foreach (var permission in policy.Permissions)
            {
                // A deny on a listed permission removes it from satisfying the any-of requirement.
                if (grants.MatchingDeny(permission) is null
                    && PermissionMatcher.IsGrantedByAny(grants.Allows, permission))
                {
                    return AuthorizationResult.Granted;
                }
            }

            return AuthorizationResult.Denied(
                $"Policy '{policy.Name}' requires any of: {string.Join(", ", policy.Permissions)}.",
                DenialReason.PolicyRequireAnyUnmet(policy.Name));
        }

        foreach (var permission in policy.Permissions)
        {
            var deny = grants.MatchingDeny(permission);
            if (deny is not null)
            {
                return AuthorizationResult.Denied(
                    $"Policy '{policy.Name}' requires '{permission}', which is explicitly denied by '{deny}'.",
                    DenialReason.ExplicitDeny(permission, deny));
            }

            if (!PermissionMatcher.IsGrantedByAny(grants.Allows, permission))
            {
                return AuthorizationResult.Denied(
                    $"Policy '{policy.Name}' requires '{permission}', which is not granted.",
                    DenialReason.PolicyRequireAllUnmet(policy.Name, permission));
            }
        }

        return AuthorizationResult.Granted;
    }
}

namespace Moongazing.OrionGrant;

using Moongazing.OrionGrant.Diagnostics;
using Moongazing.OrionGrant.Permissions;
using Moongazing.OrionGrant.Policies;

/// <summary>
/// Default <see cref="IGrantAuthorizer"/>. Expands a principal's roles through the
/// <see cref="RoleRegistry"/>, unions them with its direct permissions, and matches against the
/// requirement using <see cref="PermissionMatcher"/> wildcard semantics.
/// </summary>
public sealed class GrantAuthorizer : IGrantAuthorizer
{
    private readonly RoleRegistry roles;
    private readonly PolicyRegistry policies;
    private readonly GrantDiagnostics diagnostics;

    /// <summary>Create an authorizer.</summary>
    /// <param name="roles">The role registry.</param>
    /// <param name="policies">The policy registry.</param>
    /// <param name="diagnostics">The shared metrics instance.</param>
    public GrantAuthorizer(RoleRegistry roles, PolicyRegistry policies, GrantDiagnostics diagnostics)
    {
        ArgumentNullException.ThrowIfNull(roles);
        ArgumentNullException.ThrowIfNull(policies);
        ArgumentNullException.ThrowIfNull(diagnostics);
        this.roles = roles;
        this.policies = policies;
        this.diagnostics = diagnostics;
    }

    /// <inheritdoc />
    public IReadOnlySet<string> EffectivePermissions(GrantPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var effective = new HashSet<string>(principal.Permissions, StringComparer.Ordinal);
        foreach (var role in principal.Roles)
        {
            if (!string.IsNullOrEmpty(role))
            {
                effective.UnionWith(roles.PermissionsFor(role));
            }
        }

        return effective;
    }

    /// <inheritdoc />
    public AuthorizationResult Authorize(GrantPrincipal principal, string requiredPermission)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentException.ThrowIfNullOrEmpty(requiredPermission);

        var effective = EffectivePermissions(principal);
        return EvaluatePermission(effective, requiredPermission);
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
        var effective = EffectivePermissions(principal);

        // The base permission is a hard gate: without it, ownership is irrelevant (the IDOR fix).
        if (!PermissionMatcher.IsGrantedByAny(effective, requiredPermission))
        {
            diagnostics.Record(granted: false, "resource");
            return AuthorizationResult.Denied(
                $"Missing permission '{requiredPermission}'.",
                DenialReason.MissingPermission(requiredPermission));
        }

        // Owner OR elevated: an admin/root or a configured elevated grant bypasses ownership.
        var granted = ResourceAccess.IsElevated(effective, opts)
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

        var policy = policies.Find(policyName);
        if (policy is null)
        {
            diagnostics.Record(granted: false, "policy");
            return AuthorizationResult.Denied(
                $"Unknown policy '{policyName}'.",
                DenialReason.PolicyNotFound(policyName));
        }

        var effective = EffectivePermissions(principal);
        return EvaluatePolicy(policy, effective);
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
        var effective = EffectivePermissions(principal);
        var results = new List<BatchAuthorizationResult>(requiredPermissions.Count);
        foreach (var permission in requiredPermissions)
        {
            ArgumentException.ThrowIfNullOrEmpty(permission, nameof(requiredPermissions));
            results.Add(new BatchAuthorizationResult(permission, EvaluatePermission(effective, permission)));
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

        // The effective set is the same for every policy, so build it once for the whole batch.
        var effective = EffectivePermissions(principal);
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
                result = EvaluatePolicy(policy, effective);
            }

            results.Add(new BatchAuthorizationResult(policyName, result));
        }

        return results;
    }

    /// <summary>
    /// Evaluate one permission against an already-expanded effective set, recording the decision.
    /// Shared by the single-permission and batch paths so both apply identical semantics.
    /// </summary>
    private AuthorizationResult EvaluatePermission(IReadOnlySet<string> effective, string requiredPermission)
    {
        var granted = PermissionMatcher.IsGrantedByAny(effective, requiredPermission);
        diagnostics.Record(granted, "permission");
        return granted
            ? AuthorizationResult.Granted
            : AuthorizationResult.Denied(
                $"Missing permission '{requiredPermission}'.",
                DenialReason.MissingPermission(requiredPermission));
    }

    /// <summary>
    /// Evaluate one policy against an already-expanded effective set, recording the decision. Shared
    /// by the single-policy and batch paths.
    /// </summary>
    private AuthorizationResult EvaluatePolicy(AccessPolicy policy, IReadOnlySet<string> effective)
    {
        var result = Evaluate(policy, effective);
        diagnostics.Record(result.IsGranted, "policy");
        return result;
    }

    private static AuthorizationResult Evaluate(AccessPolicy policy, IReadOnlySet<string> effective)
    {
        if (policy.Mode == PolicyMode.RequireAny)
        {
            foreach (var permission in policy.Permissions)
            {
                if (PermissionMatcher.IsGrantedByAny(effective, permission))
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
            if (!PermissionMatcher.IsGrantedByAny(effective, permission))
            {
                return AuthorizationResult.Denied(
                    $"Policy '{policy.Name}' requires '{permission}', which is not granted.",
                    DenialReason.PolicyRequireAllUnmet(policy.Name, permission));
            }
        }

        return AuthorizationResult.Granted;
    }
}

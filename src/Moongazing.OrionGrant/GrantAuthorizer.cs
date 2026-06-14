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

        var granted = PermissionMatcher.IsGrantedByAny(EffectivePermissions(principal), requiredPermission);
        diagnostics.Record(granted, "permission");
        return granted
            ? AuthorizationResult.Granted
            : AuthorizationResult.Denied($"Missing permission '{requiredPermission}'.");
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
            return AuthorizationResult.Denied($"Unknown policy '{policyName}'.");
        }

        var effective = EffectivePermissions(principal);
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
                $"Policy '{policy.Name}' requires any of: {string.Join(", ", policy.Permissions)}.");
        }

        foreach (var permission in policy.Permissions)
        {
            if (!PermissionMatcher.IsGrantedByAny(effective, permission))
            {
                return AuthorizationResult.Denied(
                    $"Policy '{policy.Name}' requires '{permission}', which is not granted.");
            }
        }

        return AuthorizationResult.Granted;
    }
}

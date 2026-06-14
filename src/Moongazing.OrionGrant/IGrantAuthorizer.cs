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

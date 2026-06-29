namespace Moongazing.OrionGrant.AspNetCore;

using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

/// <summary>
/// An <see cref="IAuthorizationPolicyProvider"/> that materializes OrionGrant-backed policies on
/// demand from their name, so an endpoint can write <c>[Authorize(Policy = "perm:orders.read")]</c>
/// or <c>[Authorize(Policy = "policy:orders.manage")]</c> without registering each policy in
/// <c>AuthorizationOptions</c>. A name carrying the configured permission prefix yields a policy with
/// a permission <see cref="OrionGrantRequirement"/>; the policy prefix yields a named-policy
/// requirement. Any other name defers to the wrapped <see cref="DefaultAuthorizationPolicyProvider"/>,
/// so conventional registered policies keep working.
/// </summary>
public sealed class OrionGrantPolicyProvider : IAuthorizationPolicyProvider
{
    private readonly OrionGrantPolicyNameOptions options;
    private readonly DefaultAuthorizationPolicyProvider fallback;

    /// <summary>Create the provider.</summary>
    /// <param name="authorizationOptions">The framework authorization options, for the fallback provider.</param>
    /// <param name="policyNameOptions">The prefix configuration for OrionGrant policy names.</param>
    public OrionGrantPolicyProvider(
        IOptions<AuthorizationOptions> authorizationOptions,
        IOptions<OrionGrantPolicyNameOptions> policyNameOptions)
    {
        ArgumentNullException.ThrowIfNull(authorizationOptions);
        ArgumentNullException.ThrowIfNull(policyNameOptions);
        options = policyNameOptions.Value;
        fallback = new DefaultAuthorizationPolicyProvider(authorizationOptions);
    }

    /// <inheritdoc />
    public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        ArgumentNullException.ThrowIfNull(policyName);

        if (TryBuild(policyName, options.PermissionPrefix, OrionGrantRequirementKind.Permission, out var policy)
            || TryBuild(policyName, options.PolicyPrefix, OrionGrantRequirementKind.Policy, out policy))
        {
            return Task.FromResult<AuthorizationPolicy?>(policy);
        }

        return fallback.GetPolicyAsync(policyName);
    }

    /// <inheritdoc />
    public Task<AuthorizationPolicy> GetDefaultPolicyAsync() => fallback.GetDefaultPolicyAsync();

    /// <inheritdoc />
    public Task<AuthorizationPolicy?> GetFallbackPolicyAsync() => fallback.GetFallbackPolicyAsync();

    private static bool TryBuild(
        string policyName,
        string prefix,
        OrionGrantRequirementKind kind,
        out AuthorizationPolicy? policy)
    {
        policy = null;

        if (prefix.Length == 0
            || !policyName.StartsWith(prefix, StringComparison.Ordinal)
            || policyName.Length == prefix.Length)
        {
            return false;
        }

        var value = policyName[prefix.Length..];
        var requirement = kind == OrionGrantRequirementKind.Permission
            ? OrionGrantRequirement.ForPermission(value)
            : OrionGrantRequirement.ForPolicy(value);

        policy = new AuthorizationPolicyBuilder()
            .AddRequirements(requirement)
            .Build();

        return true;
    }
}

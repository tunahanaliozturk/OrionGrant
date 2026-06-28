namespace Moongazing.OrionGrant.AspNetCore;

using Microsoft.AspNetCore.Authorization;

/// <summary>
/// Extensions on <see cref="AuthorizationPolicyBuilder"/> that add an OrionGrant requirement to an
/// ASP.NET Core authorization policy, so a permission or named OrionGrant policy can gate an
/// endpoint through the standard <c>[Authorize(Policy = "...")]</c> / minimal-API pipeline.
/// </summary>
public static class OrionGrantAuthorizationPolicyBuilderExtensions
{
    /// <summary>
    /// Require the principal to hold the given OrionGrant permission. The requirement is evaluated by
    /// <see cref="OrionGrantAuthorizationHandler"/>; supplying a resource to the authorization call
    /// turns it into an object-level (ownership-aware) check.
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="permission">The required permission, for example <c>orders:read</c>.</param>
    /// <returns>The same builder, for chaining.</returns>
    public static AuthorizationPolicyBuilder RequirePermission(
        this AuthorizationPolicyBuilder builder,
        string permission)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrEmpty(permission);
        return builder.AddRequirements(OrionGrantRequirement.ForPermission(permission));
    }

    /// <summary>
    /// Require the principal to satisfy the given named OrionGrant policy (its all-of / any-of
    /// permission set, including any ABAC condition the policy carries).
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="policyName">The OrionGrant policy name, for example <c>orders.manage</c>.</param>
    /// <returns>The same builder, for chaining.</returns>
    public static AuthorizationPolicyBuilder RequirePolicy(
        this AuthorizationPolicyBuilder builder,
        string policyName)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrEmpty(policyName);
        return builder.AddRequirements(OrionGrantRequirement.ForPolicy(policyName));
    }
}

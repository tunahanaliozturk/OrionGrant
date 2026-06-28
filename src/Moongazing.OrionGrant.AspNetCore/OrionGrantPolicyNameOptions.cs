namespace Moongazing.OrionGrant.AspNetCore;

/// <summary>
/// Configures the policy-name prefixes the <see cref="OrionGrantPolicyProvider"/> recognizes when
/// turning an <c>[Authorize(Policy = "...")]</c> name into an OrionGrant requirement. A name
/// starting with <see cref="PermissionPrefix"/> becomes a permission requirement; one starting with
/// <see cref="PolicyPrefix"/> becomes a named-policy requirement. Any other name defers to the
/// default provider.
/// </summary>
public sealed class OrionGrantPolicyNameOptions
{
    /// <summary>
    /// The prefix marking a permission policy name. Defaults to <c>perm:</c>, so
    /// <c>perm:orders.read</c> requires the <c>orders.read</c> permission. An empty prefix disables
    /// permission-name resolution.
    /// </summary>
    public string PermissionPrefix { get; set; } = "perm:";

    /// <summary>
    /// The prefix marking a named-policy policy name. Defaults to <c>policy:</c>, so
    /// <c>policy:orders.manage</c> requires the OrionGrant <c>orders.manage</c> policy. An empty
    /// prefix disables policy-name resolution.
    /// </summary>
    public string PolicyPrefix { get; set; } = "policy:";
}

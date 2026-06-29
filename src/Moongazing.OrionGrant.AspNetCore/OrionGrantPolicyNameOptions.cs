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

    /// <summary>
    /// The validation message produced when either prefix is null. Used by
    /// <see cref="IsValid(OrionGrantPolicyNameOptions)"/> at registration.
    /// </summary>
    internal const string ValidationError =
        "OrionGrantPolicyNameOptions.PermissionPrefix and PolicyPrefix must not be null. Use an " +
        "empty string to disable a prefix; null is rejected because the policy provider matches " +
        "names against these prefixes.";

    /// <summary>
    /// True when neither prefix is null. An empty prefix is a legal way to disable a prefix, so only
    /// null is rejected: the provider calls <see cref="string.StartsWith(string, StringComparison)"/>
    /// with these values and a null would throw on every policy-name lookup.
    /// </summary>
    /// <param name="options">The options to validate.</param>
    internal static bool IsValid(OrionGrantPolicyNameOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return options.PermissionPrefix is not null && options.PolicyPrefix is not null;
    }
}

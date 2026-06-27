namespace Moongazing.OrionGrant.Policies;

/// <summary>How the permissions a policy lists are combined.</summary>
public enum PolicyMode
{
    /// <summary>The principal must hold every listed permission.</summary>
    RequireAll,

    /// <summary>The principal must hold at least one of the listed permissions.</summary>
    RequireAny,
}

/// <summary>
/// A named access policy: a set of permissions plus the rule for combining them. Policies let an
/// endpoint depend on a stable name (<c>orders.manage</c>) rather than hard-coding the permission
/// strings it needs.
/// </summary>
public sealed class AccessPolicy
{
    /// <summary>Create a policy.</summary>
    /// <param name="name">The policy name.</param>
    /// <param name="mode">How the permissions combine.</param>
    /// <param name="permissions">The permissions the policy requires.</param>
    public AccessPolicy(string name, PolicyMode mode, IReadOnlyCollection<string> permissions)
        : this(name, mode, permissions, condition: null)
    {
    }

    /// <summary>Create a policy with an optional attribute-based (ABAC) condition.</summary>
    /// <param name="name">The policy name.</param>
    /// <param name="mode">How the permissions combine.</param>
    /// <param name="permissions">The permissions the policy requires.</param>
    /// <param name="condition">
    /// An optional ABAC predicate evaluated after the permission requirement passes. When supplied,
    /// it is an additional AND gate: the policy grants only when both the permission requirement and
    /// the condition are satisfied. Null leaves the policy a pure permission check, identical to
    /// 0.3.0.
    /// </param>
    public AccessPolicy(
        string name,
        PolicyMode mode,
        IReadOnlyCollection<string> permissions,
        GrantCondition? condition)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(permissions);
        if (permissions.Count == 0)
        {
            throw new ArgumentException("A policy must list at least one permission.", nameof(permissions));
        }

        Name = name;
        Mode = mode;
        Permissions = permissions;
        Condition = condition;
    }

    /// <summary>The policy name.</summary>
    public string Name { get; }

    /// <summary>How the permissions combine.</summary>
    public PolicyMode Mode { get; }

    /// <summary>The permissions the policy requires.</summary>
    public IReadOnlyCollection<string> Permissions { get; }

    /// <summary>
    /// The optional attribute-based condition gating this policy, or null when the policy is a pure
    /// permission check. When present it is AND-composed with the permission requirement and is
    /// evaluated only after that requirement passes.
    /// </summary>
    public GrantCondition? Condition { get; }

    /// <summary>True when the policy carries an attribute-based condition.</summary>
    public bool HasCondition => Condition is not null;
}

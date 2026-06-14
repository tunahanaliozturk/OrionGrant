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
    }

    /// <summary>The policy name.</summary>
    public string Name { get; }

    /// <summary>How the permissions combine.</summary>
    public PolicyMode Mode { get; }

    /// <summary>The permissions the policy requires.</summary>
    public IReadOnlyCollection<string> Permissions { get; }
}

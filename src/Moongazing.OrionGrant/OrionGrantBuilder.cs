namespace Moongazing.OrionGrant;

using Moongazing.OrionGrant.Permissions;
using Moongazing.OrionGrant.Policies;

/// <summary>
/// Declares the roles and policies the authorizer knows about, evaluated once at registration to
/// build the immutable registries.
/// </summary>
public sealed class OrionGrantBuilder
{
    private readonly Dictionary<string, HashSet<string>> roles = new(StringComparer.Ordinal);
    private readonly Dictionary<string, AccessPolicy> policies = new(StringComparer.Ordinal);

    /// <summary>
    /// Define a role and the permissions it grants. Calling it again for the same role adds to its
    /// permission set.
    /// </summary>
    /// <param name="role">The role name.</param>
    /// <param name="permissions">The permissions the role grants.</param>
    public OrionGrantBuilder AddRole(string role, params string[] permissions)
    {
        ArgumentException.ThrowIfNullOrEmpty(role);
        ArgumentNullException.ThrowIfNull(permissions);

        if (!roles.TryGetValue(role, out var set))
        {
            set = new HashSet<string>(StringComparer.Ordinal);
            roles[role] = set;
        }
        foreach (var permission in permissions)
        {
            if (!string.IsNullOrEmpty(permission))
            {
                set.Add(permission);
            }
        }

        return this;
    }

    /// <summary>Define a named access policy.</summary>
    /// <param name="name">The policy name.</param>
    /// <param name="mode">How the permissions combine.</param>
    /// <param name="permissions">The permissions the policy requires.</param>
    public OrionGrantBuilder AddPolicy(string name, PolicyMode mode, params string[] permissions)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        policies[name] = new AccessPolicy(name, mode, permissions);
        return this;
    }

    internal RoleRegistry BuildRoles()
    {
        var map = new Dictionary<string, IReadOnlySet<string>>(StringComparer.Ordinal);
        foreach (var (role, set) in roles)
        {
            map[role] = set;
        }

        return new RoleRegistry(map);
    }

    internal PolicyRegistry BuildPolicies() =>
        new(new Dictionary<string, AccessPolicy>(policies, StringComparer.Ordinal));
}

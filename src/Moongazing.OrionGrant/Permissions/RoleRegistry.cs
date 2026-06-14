namespace Moongazing.OrionGrant.Permissions;

/// <summary>
/// An immutable map from role name to the permissions that role grants. Built once at startup from
/// the registration builder and resolved during authorization to expand a principal's roles.
/// </summary>
public sealed class RoleRegistry
{
    private readonly IReadOnlyDictionary<string, IReadOnlySet<string>> roles;

    /// <summary>Create a registry from role definitions.</summary>
    /// <param name="roles">The role-to-permissions map.</param>
    public RoleRegistry(IReadOnlyDictionary<string, IReadOnlySet<string>> roles)
    {
        ArgumentNullException.ThrowIfNull(roles);
        this.roles = roles;
    }

    /// <summary>An empty registry (no roles defined).</summary>
    public static RoleRegistry Empty { get; } =
        new(new Dictionary<string, IReadOnlySet<string>>(StringComparer.Ordinal));

    /// <summary>Get the permissions a role grants, or an empty set for an unknown role.</summary>
    /// <param name="role">The role name.</param>
    public IReadOnlySet<string> PermissionsFor(string role)
    {
        ArgumentException.ThrowIfNullOrEmpty(role);
        return roles.TryGetValue(role, out var permissions)
            ? permissions
            : System.Collections.Frozen.FrozenSet<string>.Empty;
    }

    /// <summary>The defined role names.</summary>
    public IEnumerable<string> Roles => roles.Keys;
}

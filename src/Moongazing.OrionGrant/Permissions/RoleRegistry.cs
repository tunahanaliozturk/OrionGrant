namespace Moongazing.OrionGrant.Permissions;

/// <summary>
/// An immutable map from role name to the permissions that role grants. Built once at startup from
/// the registration builder and resolved during authorization to expand a principal's roles.
/// </summary>
/// <remarks>
/// When roles include other roles, the inclusion is resolved into each role's permission set at
/// build time, so <see cref="PermissionsFor"/> already returns the transitive permissions and the
/// authorization hot path stays a single set lookup with no graph walk. The declared inclusion
/// edges are retained for introspection via <see cref="IncludedRolesFor"/>.
/// </remarks>
public sealed class RoleRegistry
{
    private static readonly IReadOnlyList<string> NoIncludedRoles = [];

    private readonly IReadOnlyDictionary<string, IReadOnlySet<string>> roles;
    private readonly IReadOnlyDictionary<string, IReadOnlyList<string>> inclusions;

    /// <summary>Create a registry from role definitions.</summary>
    /// <param name="roles">The role-to-permissions map.</param>
    public RoleRegistry(IReadOnlyDictionary<string, IReadOnlySet<string>> roles)
        : this(roles, new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal))
    {
    }

    /// <summary>Create a registry from role definitions and their declared inclusion edges.</summary>
    /// <param name="roles">
    /// The role-to-permissions map. When inclusion is in play these are the already-flattened
    /// (transitive) permission sets, so a lookup needs no further expansion.
    /// </param>
    /// <param name="inclusions">
    /// The role-to-included-roles map, retained for introspection. Pass an empty map when no role
    /// includes another.
    /// </param>
    public RoleRegistry(
        IReadOnlyDictionary<string, IReadOnlySet<string>> roles,
        IReadOnlyDictionary<string, IReadOnlyList<string>> inclusions)
    {
        ArgumentNullException.ThrowIfNull(roles);
        ArgumentNullException.ThrowIfNull(inclusions);
        this.roles = roles;
        this.inclusions = inclusions;
    }

    /// <summary>An empty registry (no roles defined).</summary>
    public static RoleRegistry Empty { get; } =
        new(new Dictionary<string, IReadOnlySet<string>>(StringComparer.Ordinal));

    /// <summary>
    /// Get the permissions a role grants, or an empty set for an unknown role. When the role
    /// includes other roles, the returned set already contains their permissions transitively.
    /// </summary>
    /// <param name="role">The role name.</param>
    public IReadOnlySet<string> PermissionsFor(string role)
    {
        ArgumentException.ThrowIfNullOrEmpty(role);
        return roles.TryGetValue(role, out var permissions)
            ? permissions
            : System.Collections.Frozen.FrozenSet<string>.Empty;
    }

    /// <summary>
    /// Get the roles a role directly includes (its declared inclusion edges, not the transitive
    /// closure), or an empty list when it includes none or is unknown.
    /// </summary>
    /// <param name="role">The role name.</param>
    public IReadOnlyList<string> IncludedRolesFor(string role)
    {
        ArgumentException.ThrowIfNullOrEmpty(role);
        return inclusions.TryGetValue(role, out var included) ? included : NoIncludedRoles;
    }

    /// <summary>The defined role names.</summary>
    public IEnumerable<string> Roles => roles.Keys;
}

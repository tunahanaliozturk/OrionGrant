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
    private readonly Dictionary<string, List<string>> inclusions = new(StringComparer.Ordinal);
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

        var set = OwnPermissions(role);
        foreach (var permission in permissions)
        {
            if (!string.IsNullOrEmpty(permission))
            {
                set.Add(permission);
            }
        }

        return this;
    }

    /// <summary>
    /// Compose roles: declare that <paramref name="role"/> includes the permissions of every role in
    /// <paramref name="includedRoles"/>. Inclusion is transitive (if <c>a</c> includes <c>b</c> and
    /// <c>b</c> includes <c>c</c>, then <c>a</c> grants <c>c</c>'s permissions) and is resolved into
    /// the effective permission set once at <see cref="BuildRoles"/> time. Calling it again for the
    /// same role adds to the set of roles it includes; declaring an inclusion does not require the
    /// included role to be defined with <see cref="AddRole"/>, an undefined included role simply
    /// contributes nothing.
    /// </summary>
    /// <param name="role">The including role.</param>
    /// <param name="includedRoles">The roles whose permissions are folded into it.</param>
    /// <remarks>
    /// Cycles (a role that includes itself directly or transitively) are rejected at
    /// <see cref="BuildRoles"/> time with a <see cref="RoleInclusionCycleException"/>, so a
    /// misconfiguration fails fast at startup rather than looping during a request.
    /// </remarks>
    public OrionGrantBuilder IncludeRole(string role, params string[] includedRoles)
    {
        ArgumentException.ThrowIfNullOrEmpty(role);
        ArgumentNullException.ThrowIfNull(includedRoles);

        // Ensure the including role exists as a node even if it has no own permissions yet.
        _ = OwnPermissions(role);

        if (!inclusions.TryGetValue(role, out var included))
        {
            included = [];
            inclusions[role] = included;
        }
        foreach (var includedRole in includedRoles)
        {
            if (!string.IsNullOrEmpty(includedRole) && !included.Contains(includedRole))
            {
                included.Add(includedRole);
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

    private HashSet<string> OwnPermissions(string role)
    {
        if (!roles.TryGetValue(role, out var set))
        {
            set = new HashSet<string>(StringComparer.Ordinal);
            roles[role] = set;
        }

        return set;
    }

    internal RoleRegistry BuildRoles()
    {
        var map = new Dictionary<string, IReadOnlySet<string>>(StringComparer.Ordinal);

        if (inclusions.Count == 0)
        {
            // No composition: each role's effective set is exactly its own permissions.
            foreach (var (role, set) in roles)
            {
                map[role] = set;
            }

            return new RoleRegistry(map);
        }

        var resolver = new InclusionResolver(roles, inclusions);
        foreach (var role in roles.Keys)
        {
            map[role] = resolver.Resolve(role);
        }

        var declaredInclusions = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        foreach (var (role, included) in inclusions)
        {
            if (included.Count > 0)
            {
                declaredInclusions[role] = included.ToArray();
            }
        }

        return new RoleRegistry(map, declaredInclusions);
    }

    internal PolicyRegistry BuildPolicies() =>
        new(new Dictionary<string, AccessPolicy>(policies, StringComparer.Ordinal));

    /// <summary>
    /// Resolves each role's transitive permission set by folding in the permissions of every role it
    /// includes, depth-first, while detecting inclusion cycles. Results are memoized so a diamond
    /// inclusion (two roles including a common third) resolves the shared role once.
    /// </summary>
    private sealed class InclusionResolver
    {
        private readonly IReadOnlyDictionary<string, HashSet<string>> ownPermissions;
        private readonly IReadOnlyDictionary<string, List<string>> includes;
        private readonly Dictionary<string, IReadOnlySet<string>> resolved = new(StringComparer.Ordinal);
        private readonly HashSet<string> onStack = new(StringComparer.Ordinal);
        private readonly List<string> path = [];

        internal InclusionResolver(
            IReadOnlyDictionary<string, HashSet<string>> ownPermissions,
            IReadOnlyDictionary<string, List<string>> includes)
        {
            this.ownPermissions = ownPermissions;
            this.includes = includes;
        }

        internal IReadOnlySet<string> Resolve(string role)
        {
            if (resolved.TryGetValue(role, out var cached))
            {
                return cached;
            }

            if (!onStack.Add(role))
            {
                // The role is already on the active recursion stack: close the cycle on it and fail.
                var start = path.IndexOf(role);
                var cycle = path.GetRange(start, path.Count - start);
                cycle.Add(role);
                throw new RoleInclusionCycleException(cycle);
            }

            path.Add(role);

            var effective = ownPermissions.TryGetValue(role, out var own)
                ? new HashSet<string>(own, StringComparer.Ordinal)
                : new HashSet<string>(StringComparer.Ordinal);

            if (includes.TryGetValue(role, out var included))
            {
                foreach (var child in included)
                {
                    effective.UnionWith(Resolve(child));
                }
            }

            path.RemoveAt(path.Count - 1);
            onStack.Remove(role);

            IReadOnlySet<string> result = effective;
            resolved[role] = result;
            return result;
        }
    }
}

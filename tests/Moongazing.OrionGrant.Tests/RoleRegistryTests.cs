namespace Moongazing.OrionGrant.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Moongazing.OrionGrant.Permissions;

using Xunit;

/// <summary>
/// Coverage of <see cref="RoleRegistry"/>: lookups, the empty-set fallback for unknown roles, the
/// shared empty registry, role enumeration, and argument validation.
/// </summary>
public sealed class RoleRegistryTests
{
    private static RoleRegistry Registry(params (string Role, string[] Permissions)[] entries)
    {
        var map = new Dictionary<string, IReadOnlySet<string>>(StringComparer.Ordinal);
        foreach (var (role, permissions) in entries)
        {
            map[role] = new HashSet<string>(permissions, StringComparer.Ordinal);
        }

        return new RoleRegistry(map);
    }

    [Fact]
    public void PermissionsFor_returns_the_roles_permissions()
    {
        var registry = Registry(("reader", ["orders:read", "billing:read"]));

        var permissions = registry.PermissionsFor("reader");

        Assert.Equal(2, permissions.Count);
        Assert.Contains("orders:read", permissions);
        Assert.Contains("billing:read", permissions);
    }

    [Fact]
    public void PermissionsFor_unknown_role_returns_an_empty_set()
    {
        var registry = Registry(("reader", ["orders:read"]));

        Assert.Empty(registry.PermissionsFor("ghost"));
    }

    [Fact]
    public void PermissionsFor_is_case_sensitive()
    {
        var registry = Registry(("Reader", ["orders:read"]));

        Assert.Empty(registry.PermissionsFor("reader"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void PermissionsFor_throws_when_role_is_null_or_empty(string? role)
    {
        var registry = Registry(("reader", ["orders:read"]));

        // ThrowIfNullOrEmpty throws ArgumentNullException for null, ArgumentException for empty.
        Assert.ThrowsAny<ArgumentException>(() => registry.PermissionsFor(role!));
    }

    [Fact]
    public void Roles_enumerates_the_defined_role_names()
    {
        var registry = Registry(("reader", ["orders:read"]), ("writer", ["orders:write"]));

        var names = registry.Roles.OrderBy(n => n, StringComparer.Ordinal).ToArray();

        Assert.Equal(["reader", "writer"], names);
    }

    [Fact]
    public void Empty_registry_has_no_roles_and_returns_empty_permission_sets()
    {
        Assert.Empty(RoleRegistry.Empty.Roles);
        Assert.Empty(RoleRegistry.Empty.PermissionsFor("anything"));
    }

    [Fact]
    public void Constructor_throws_when_map_is_null()
    {
        Assert.Throws<ArgumentNullException>(() => new RoleRegistry(null!));
    }

    [Fact]
    public void Mutating_the_source_collections_after_construction_does_not_change_the_registry()
    {
        // The registry must own immutable snapshots of the caller's collections. If it stored them
        // by reference, a later mutation of the source dictionary or any inner set (e.g. a reused
        // builder path) could silently change resolved authorization outcomes at runtime.
        var readerPermissions = new HashSet<string>(["orders:read"], StringComparer.Ordinal);
        var roles = new Dictionary<string, IReadOnlySet<string>>(StringComparer.Ordinal)
        {
            ["reader"] = readerPermissions,
        };
        var inclusions = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
        {
            ["reader"] = new List<string> { "base" },
        };

        var registry = new RoleRegistry(roles, inclusions);

        // Mutate every caller-owned collection the registry was built from.
        readerPermissions.Add("orders:write");          // inner permission set
        roles["reader"] = new HashSet<string>(StringComparer.Ordinal); // outer roles map value
        roles["admin"] = new HashSet<string>(["*"], StringComparer.Ordinal); // new outer key
        ((List<string>)inclusions["reader"]).Add("elevated"); // inner inclusion list
        inclusions["writer"] = new List<string> { "base" };  // new outer key

        // Resolved permissions reflect only the construction-time snapshot.
        var permissions = registry.PermissionsFor("reader");
        Assert.Equal(["orders:read"], permissions.OrderBy(p => p, StringComparer.Ordinal).ToArray());

        // Declared inclusions likewise unchanged.
        Assert.Equal(["base"], registry.IncludedRolesFor("reader"));

        // Keys added to the source after construction did not leak in.
        Assert.Empty(registry.PermissionsFor("admin"));
        Assert.Empty(registry.IncludedRolesFor("writer"));
        Assert.Equal(["reader"], registry.Roles.OrderBy(n => n, StringComparer.Ordinal).ToArray());
    }
}

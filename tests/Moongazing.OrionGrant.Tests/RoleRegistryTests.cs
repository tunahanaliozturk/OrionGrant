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
}

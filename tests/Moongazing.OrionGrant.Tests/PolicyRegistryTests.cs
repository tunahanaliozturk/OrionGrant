namespace Moongazing.OrionGrant.Tests;

using System;
using System.Collections.Generic;

using Moongazing.OrionGrant.Policies;

using Xunit;

/// <summary>
/// Coverage of <see cref="PolicyRegistry"/>: lookups, the null result for an unknown policy, the
/// shared empty registry, case sensitivity, and argument validation.
/// </summary>
public sealed class PolicyRegistryTests
{
    private static PolicyRegistry Registry(params AccessPolicy[] policies)
    {
        var map = new Dictionary<string, AccessPolicy>(StringComparer.Ordinal);
        foreach (var policy in policies)
        {
            map[policy.Name] = policy;
        }

        return new PolicyRegistry(map);
    }

    [Fact]
    public void Find_returns_a_registered_policy()
    {
        var policy = new AccessPolicy("orders.manage", PolicyMode.RequireAll, ["orders:write"]);
        var registry = Registry(policy);

        Assert.Same(policy, registry.Find("orders.manage"));
    }

    [Fact]
    public void Find_returns_null_for_an_unknown_policy()
    {
        var registry = Registry(new AccessPolicy("orders.manage", PolicyMode.RequireAll, ["orders:write"]));

        Assert.Null(registry.Find("missing"));
    }

    [Fact]
    public void Find_is_case_sensitive()
    {
        var registry = Registry(new AccessPolicy("orders.manage", PolicyMode.RequireAll, ["orders:write"]));

        Assert.Null(registry.Find("Orders.Manage"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Find_throws_when_name_is_null_or_empty(string? name)
    {
        var registry = Registry(new AccessPolicy("orders.manage", PolicyMode.RequireAll, ["orders:write"]));

        // ThrowIfNullOrEmpty throws ArgumentNullException for null, ArgumentException for empty.
        Assert.ThrowsAny<ArgumentException>(() => registry.Find(name!));
    }

    [Fact]
    public void Empty_registry_finds_nothing()
    {
        Assert.Null(PolicyRegistry.Empty.Find("anything"));
    }

    [Fact]
    public void Constructor_throws_when_map_is_null()
    {
        Assert.Throws<ArgumentNullException>(() => new PolicyRegistry(null!));
    }
}

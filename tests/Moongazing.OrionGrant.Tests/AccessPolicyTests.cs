namespace Moongazing.OrionGrant.Tests;

using System;

using Moongazing.OrionGrant.Policies;

using Xunit;

/// <summary>
/// Coverage of <see cref="AccessPolicy"/> construction: property round-tripping, both modes, and
/// argument validation (name required, permissions non-null and non-empty).
/// </summary>
public sealed class AccessPolicyTests
{
    [Fact]
    public void Constructor_round_trips_name_mode_and_permissions()
    {
        var policy = new AccessPolicy("orders.manage", PolicyMode.RequireAll, ["orders:read", "orders:write"]);

        Assert.Equal("orders.manage", policy.Name);
        Assert.Equal(PolicyMode.RequireAll, policy.Mode);
        Assert.Equal(2, policy.Permissions.Count);
        Assert.Contains("orders:read", policy.Permissions);
        Assert.Contains("orders:write", policy.Permissions);
    }

    [Fact]
    public void Constructor_accepts_require_any_mode()
    {
        var policy = new AccessPolicy("orders.touch", PolicyMode.RequireAny, ["orders:read"]);

        Assert.Equal(PolicyMode.RequireAny, policy.Mode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Constructor_throws_when_name_is_null_or_empty(string? name)
    {
        // ThrowIfNullOrEmpty throws ArgumentNullException for null, ArgumentException for empty.
        Assert.ThrowsAny<ArgumentException>(
            () => new AccessPolicy(name!, PolicyMode.RequireAll, ["orders:read"]));
    }

    [Fact]
    public void Constructor_throws_when_permissions_is_null()
    {
        Assert.Throws<ArgumentNullException>(
            () => new AccessPolicy("orders.manage", PolicyMode.RequireAll, null!));
    }

    [Fact]
    public void Constructor_throws_when_permissions_is_empty()
    {
        Assert.Throws<ArgumentException>(
            () => new AccessPolicy("orders.manage", PolicyMode.RequireAll, []));
    }
}

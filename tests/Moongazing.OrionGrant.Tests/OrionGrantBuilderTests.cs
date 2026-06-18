namespace Moongazing.OrionGrant.Tests;

using System;
using System.Linq;

using Moongazing.OrionGrant;
using Moongazing.OrionGrant.Policies;

using Xunit;

/// <summary>
/// Coverage of <see cref="OrionGrantBuilder"/>: fluent chaining, additive role definitions,
/// empty-permission filtering, the last-write-wins policy behaviour, and argument validation. The
/// builder is exercised through the registries it produces, which is how the authorizer consumes it.
/// </summary>
public sealed class OrionGrantBuilderTests
{
    [Fact]
    public void AddRole_and_AddPolicy_return_the_builder_for_chaining()
    {
        var builder = new OrionGrantBuilder();

        var chained = builder
            .AddRole("reader", "orders:read")
            .AddPolicy("orders.read", PolicyMode.RequireAny, "orders:read");

        Assert.Same(builder, chained);
    }

    [Fact]
    public void BuildRoles_exposes_a_defined_role_with_its_permissions()
    {
        var registry = new OrionGrantBuilder()
            .AddRole("reader", "orders:read", "billing:read")
            .BuildRoles();

        var permissions = registry.PermissionsFor("reader");

        Assert.Equal(2, permissions.Count);
        Assert.Contains("orders:read", permissions);
        Assert.Contains("billing:read", permissions);
    }

    [Fact]
    public void AddRole_called_twice_unions_the_permission_sets()
    {
        var registry = new OrionGrantBuilder()
            .AddRole("reader", "orders:read")
            .AddRole("reader", "billing:read")
            .BuildRoles();

        var permissions = registry.PermissionsFor("reader");

        Assert.Equal(2, permissions.Count);
        Assert.Contains("orders:read", permissions);
        Assert.Contains("billing:read", permissions);
    }

    [Fact]
    public void AddRole_deduplicates_repeated_permissions()
    {
        var registry = new OrionGrantBuilder()
            .AddRole("reader", "orders:read", "orders:read")
            .BuildRoles();

        Assert.Single(registry.PermissionsFor("reader"));
    }

    [Fact]
    public void AddRole_filters_out_null_and_empty_permissions()
    {
        var registry = new OrionGrantBuilder()
            .AddRole("reader", "orders:read", "", null!)
            .BuildRoles();

        Assert.Single(registry.PermissionsFor("reader"));
        Assert.Contains("orders:read", registry.PermissionsFor("reader"));
    }

    [Fact]
    public void AddRole_with_no_permissions_still_defines_the_role()
    {
        var registry = new OrionGrantBuilder()
            .AddRole("placeholder")
            .BuildRoles();

        Assert.Contains("placeholder", registry.Roles);
        Assert.Empty(registry.PermissionsFor("placeholder"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void AddRole_throws_when_role_name_is_null_or_empty(string? role)
    {
        var builder = new OrionGrantBuilder();

        // ThrowIfNullOrEmpty throws ArgumentNullException for null, ArgumentException for empty.
        Assert.ThrowsAny<ArgumentException>(() => builder.AddRole(role!, "orders:read"));
    }

    [Fact]
    public void AddRole_throws_when_permissions_array_is_null()
    {
        var builder = new OrionGrantBuilder();

        Assert.Throws<ArgumentNullException>(() => builder.AddRole("reader", null!));
    }

    [Fact]
    public void BuildPolicies_exposes_a_defined_policy()
    {
        var registry = new OrionGrantBuilder()
            .AddPolicy("orders.manage", PolicyMode.RequireAll, "orders:read", "orders:write")
            .BuildPolicies();

        var policy = registry.Find("orders.manage");

        Assert.NotNull(policy);
        Assert.Equal(PolicyMode.RequireAll, policy!.Mode);
        Assert.Equal(2, policy.Permissions.Count);
    }

    [Fact]
    public void AddPolicy_called_twice_for_the_same_name_keeps_the_last_definition()
    {
        var registry = new OrionGrantBuilder()
            .AddPolicy("orders.manage", PolicyMode.RequireAll, "orders:read")
            .AddPolicy("orders.manage", PolicyMode.RequireAny, "orders:write")
            .BuildPolicies();

        var policy = registry.Find("orders.manage");

        Assert.NotNull(policy);
        Assert.Equal(PolicyMode.RequireAny, policy!.Mode);
        Assert.Contains("orders:write", policy.Permissions);
        Assert.DoesNotContain("orders:read", policy.Permissions);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void AddPolicy_throws_when_name_is_null_or_empty(string? name)
    {
        var builder = new OrionGrantBuilder();

        // ThrowIfNullOrEmpty throws ArgumentNullException for null, ArgumentException for empty.
        Assert.ThrowsAny<ArgumentException>(
            () => builder.AddPolicy(name!, PolicyMode.RequireAll, "orders:read"));
    }

    [Fact]
    public void AddPolicy_throws_when_it_lists_no_permissions()
    {
        var builder = new OrionGrantBuilder();

        // AccessPolicy rejects an empty permission set; the builder surfaces that.
        Assert.Throws<ArgumentException>(
            () => builder.AddPolicy("orders.manage", PolicyMode.RequireAll));
    }

    [Fact]
    public void Building_an_unconfigured_builder_yields_empty_registries()
    {
        var builder = new OrionGrantBuilder();

        Assert.Empty(builder.BuildRoles().Roles);
        Assert.Null(builder.BuildPolicies().Find("anything"));
    }
}

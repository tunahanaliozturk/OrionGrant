namespace Moongazing.OrionGrant.AspNetCore.Tests;

using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

using Xunit;

/// <summary>
/// Verifies the <c>RequirePermission</c> / <c>RequirePolicy</c> builder extensions add an
/// <see cref="OrionGrantRequirement"/> to an authorization policy, and that a policy built that way
/// evaluates through the real <see cref="IAuthorizationService"/>.
/// </summary>
public sealed class PolicyBuilderExtensionsTests
{
    [Fact]
    public void require_permission_adds_a_permission_requirement()
    {
        var policy = new AuthorizationPolicyBuilder()
            .RequirePermission("orders:read")
            .Build();

        var requirement = Assert.IsType<OrionGrantRequirement>(Assert.Single(policy.Requirements));
        Assert.Equal(OrionGrantRequirementKind.Permission, requirement.Kind);
        Assert.Equal("orders:read", requirement.Value);
    }

    [Fact]
    public void require_policy_adds_a_policy_requirement()
    {
        var policy = new AuthorizationPolicyBuilder()
            .RequirePolicy("orders.manage")
            .Build();

        var requirement = Assert.IsType<OrionGrantRequirement>(Assert.Single(policy.Requirements));
        Assert.Equal(OrionGrantRequirementKind.Policy, requirement.Kind);
        Assert.Equal("orders.manage", requirement.Value);
    }

    [Fact]
    public async Task a_registered_policy_built_with_require_permission_authorizes_through_the_service()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthorization(options => options.AddPolicy(
            "OrdersRead",
            builder => builder.RequirePermission("orders:read")));
        services.AddOrionGrantAuthorization();
        await using var provider = services.BuildServiceProvider();
        var auth = provider.GetRequiredService<IAuthorizationService>();

        var granted = await auth.AuthorizeAsync(
            TestPrincipals.With("alice", permissions: ["orders:read"]), "OrdersRead");
        var denied = await auth.AuthorizeAsync(
            TestPrincipals.With("bob", permissions: ["billing:read"]), "OrdersRead");

        Assert.True(granted.Succeeded);
        Assert.False(denied.Succeeded);
    }
}

namespace Moongazing.OrionGrant.AspNetCore.Tests;

using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

using Moongazing.OrionGrant.Policies;

using Xunit;

/// <summary>
/// Verifies that <c>[Authorize(Policy = "perm:...")]</c> / <c>"policy:..."</c> names resolve through
/// the <see cref="OrionGrantPolicyProvider"/> to OrionGrant checks, and that unrecognized names fall
/// back to the default provider's registered policies.
/// </summary>
public sealed class PolicyProviderTests
{
    private static ServiceProvider BuildProvider(Action<OrionGrantBuilder>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthorization(options => options.AddPolicy(
            "Registered",
            policy => policy.RequireAssertion(_ => true)));
        services.AddOrionGrantAuthorization(configure);
        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task permission_prefixed_name_resolves_to_a_permission_requirement()
    {
        await using var provider = BuildProvider();
        var policyProvider = provider.GetRequiredService<IAuthorizationPolicyProvider>();

        var policy = await policyProvider.GetPolicyAsync("perm:orders.read");

        Assert.NotNull(policy);
        var requirement = Assert.IsType<OrionGrantRequirement>(Assert.Single(policy!.Requirements));
        Assert.Equal(OrionGrantRequirementKind.Permission, requirement.Kind);
        Assert.Equal("orders.read", requirement.Value);
    }

    [Fact]
    public async Task policy_prefixed_name_resolves_to_a_policy_requirement()
    {
        await using var provider = BuildProvider();
        var policyProvider = provider.GetRequiredService<IAuthorizationPolicyProvider>();

        var policy = await policyProvider.GetPolicyAsync("policy:orders.manage");

        Assert.NotNull(policy);
        var requirement = Assert.IsType<OrionGrantRequirement>(Assert.Single(policy!.Requirements));
        Assert.Equal(OrionGrantRequirementKind.Policy, requirement.Kind);
        Assert.Equal("orders.manage", requirement.Value);
    }

    [Fact]
    public async Task unrecognized_name_falls_back_to_the_default_provider()
    {
        await using var provider = BuildProvider();
        var policyProvider = provider.GetRequiredService<IAuthorizationPolicyProvider>();

        var registered = await policyProvider.GetPolicyAsync("Registered");
        var unknown = await policyProvider.GetPolicyAsync("DoesNotExist");

        Assert.NotNull(registered);
        Assert.Null(unknown);
    }

    [Fact]
    public async Task perm_prefixed_policy_name_evaluates_through_the_authorization_service()
    {
        await using var provider = BuildProvider();
        var auth = provider.GetRequiredService<IAuthorizationService>();
        var granted = TestPrincipals.With("alice", permissions: ["orders.read"]);
        var denied = TestPrincipals.With("bob", permissions: ["orders.write"]);

        var grantedResult = await auth.AuthorizeAsync(granted, "perm:orders.read");
        var deniedResult = await auth.AuthorizeAsync(denied, "perm:orders.read");

        Assert.True(grantedResult.Succeeded);
        Assert.False(deniedResult.Succeeded);
    }

    [Fact]
    public async Task policy_prefixed_policy_name_evaluates_a_named_orion_policy_through_the_service()
    {
        await using var provider = BuildProvider(b => b.AddPolicy(
            "orders.manage",
            PolicyMode.RequireAny,
            ["orders:admin", "orders:write"]));
        var auth = provider.GetRequiredService<IAuthorizationService>();
        var user = TestPrincipals.With("alice", permissions: ["orders:write"]);

        var result = await auth.AuthorizeAsync(user, "policy:orders.manage");

        Assert.True(result.Succeeded);
    }
}

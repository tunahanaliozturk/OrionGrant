namespace Moongazing.OrionGrant.AspNetCore.Tests;

using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

using Moongazing.OrionGrant.Policies;

using Xunit;

/// <summary>
/// Exercises the bridge through the real <see cref="IAuthorizationService"/> resolved from a DI
/// container configured with <c>AddOrionGrantAuthorization</c>, the same seam an application uses.
/// </summary>
public sealed class AuthorizationServiceIntegrationTests
{
    private static IAuthorizationService BuildAuthorizationService(Action<OrionGrantBuilder>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthorization();
        services.AddOrionGrantAuthorization(configure);
        return services.BuildServiceProvider().GetRequiredService<IAuthorizationService>();
    }

    [Fact]
    public async Task principal_with_required_permission_is_authorized()
    {
        var auth = BuildAuthorizationService();
        var user = TestPrincipals.With("alice", permissions: ["orders:read"]);

        var result = await auth.AuthorizeAsync(
            user,
            resource: null,
            OrionGrantRequirement.ForPermission("orders:read"));

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task principal_without_required_permission_is_forbidden()
    {
        var auth = BuildAuthorizationService();
        var user = TestPrincipals.With("bob", permissions: ["orders:write"]);

        var result = await auth.AuthorizeAsync(
            user,
            resource: null,
            OrionGrantRequirement.ForPermission("orders:read"));

        Assert.False(result.Succeeded);
        var reason = Assert.IsType<OrionGrantAuthorizationFailureReason>(
            Assert.Single(result.Failure!.FailureReasons));
        Assert.Equal(DenialKind.MissingPermission, reason.Denial!.Kind);
        Assert.Equal("orders:read", reason.Denial.Permission);
    }

    [Fact]
    public async Task anonymous_principal_is_forbidden()
    {
        var auth = BuildAuthorizationService();

        var result = await auth.AuthorizeAsync(
            TestPrincipals.Anonymous(),
            resource: null,
            OrionGrantRequirement.ForPermission("orders:read"));

        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task named_policy_requirement_resolves_and_evaluates()
    {
        var auth = BuildAuthorizationService(b => b.AddPolicy(
            "orders.manage",
            PolicyMode.RequireAll,
            ["orders:read", "orders:write"]));

        var granted = TestPrincipals.With("alice", permissions: ["orders:read", "orders:write"]);
        var missing = TestPrincipals.With("bob", permissions: ["orders:read"]);

        var grantedResult = await auth.AuthorizeAsync(
            granted, resource: null, OrionGrantRequirement.ForPolicy("orders.manage"));
        var deniedResult = await auth.AuthorizeAsync(
            missing, resource: null, OrionGrantRequirement.ForPolicy("orders.manage"));

        Assert.True(grantedResult.Succeeded);
        Assert.False(deniedResult.Succeeded);
        var reason = Assert.IsType<OrionGrantAuthorizationFailureReason>(
            Assert.Single(deniedResult.Failure!.FailureReasons));
        Assert.Equal(DenialKind.PolicyRequirementUnmet, reason.Denial!.Kind);
        Assert.Equal("orders.manage", reason.Denial.PolicyName);
    }

    [Fact]
    public async Task resource_based_authorization_honors_object_level_grant_for_owner()
    {
        var auth = BuildAuthorizationService();
        var user = TestPrincipals.With("alice", permissions: ["accounts:read"]);
        var ownedResource = new OrionGrantResource(ResourceContext.OwnedBy("alice"));

        var result = await auth.AuthorizeAsync(
            user,
            ownedResource,
            OrionGrantRequirement.ForPermission("accounts:read"));

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task resource_based_authorization_forbids_non_owner_without_elevation()
    {
        var auth = BuildAuthorizationService();
        var user = TestPrincipals.With("alice", permissions: ["accounts:read"]);
        var othersResource = new OrionGrantResource(
            new ResourceContext(ownerId: "mallory", resourceType: "account", resourceId: "42"));

        var result = await auth.AuthorizeAsync(
            user,
            othersResource,
            OrionGrantRequirement.ForPermission("accounts:read"));

        Assert.False(result.Succeeded);
        var reason = Assert.IsType<OrionGrantAuthorizationFailureReason>(
            Assert.Single(result.Failure!.FailureReasons));
        Assert.Equal(DenialKind.ResourceOwnership, reason.Denial!.Kind);
        Assert.Equal("42", reason.Denial.ResourceId);
    }

    [Fact]
    public async Task bare_resource_context_is_treated_as_an_object_level_check()
    {
        var auth = BuildAuthorizationService();
        var user = TestPrincipals.With("alice", permissions: ["accounts:read"]);

        var owned = await auth.AuthorizeAsync(
            user, ResourceContext.OwnedBy("alice"), OrionGrantRequirement.ForPermission("accounts:read"));
        var foreign = await auth.AuthorizeAsync(
            user, ResourceContext.OwnedBy("mallory"), OrionGrantRequirement.ForPermission("accounts:read"));

        Assert.True(owned.Succeeded);
        Assert.False(foreign.Succeeded);
    }

    [Fact]
    public async Task explicit_deny_produces_a_failure_carrying_the_reason()
    {
        var auth = BuildAuthorizationService();
        var user = TestPrincipals.With(
            "alice",
            permissions: ["orders:read"],
            denies: ["orders:*"]);

        var result = await auth.AuthorizeAsync(
            user,
            resource: null,
            OrionGrantRequirement.ForPermission("orders:read"));

        Assert.False(result.Succeeded);
        var reason = Assert.IsType<OrionGrantAuthorizationFailureReason>(
            Assert.Single(result.Failure!.FailureReasons));
        Assert.Equal(DenialKind.ExplicitDeny, reason.Denial!.Kind);
        Assert.Equal("orders:*", reason.Denial.DenyPattern);
        Assert.Equal(reason.Result.FailureReason, reason.Message);
    }
}

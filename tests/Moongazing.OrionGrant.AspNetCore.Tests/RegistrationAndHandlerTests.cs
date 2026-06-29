namespace Moongazing.OrionGrant.AspNetCore.Tests;

using System.Security.Claims;

using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

using Moongazing.OrionGrant.Policies;

using Xunit;

/// <summary>
/// Covers the v0.5.0 review fixes on the ASP.NET Core integration: one-call registration, the scoped
/// handler resolving scoped dependencies without a captive-dependency failure, resource attributes
/// reaching an ABAC policy condition, fail-closed handling of an unsupported resource type, option
/// validation at startup, the subject-claim fallback to <c>sub</c>, and a policy denial reporting a
/// policy reason rather than a missing-permission reason.
/// </summary>
public sealed class RegistrationAndHandlerTests
{
    [Fact]
    public async Task add_orion_grant_authorization_alone_wires_a_working_integration()
    {
        // No separate AddAuthorization call: the single AddOrionGrantAuthorization must register the
        // framework authorization services (IAuthorizationService) itself, plus the handler, resolver,
        // and policy provider, so a permission requirement evaluates end to end.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOrionGrantAuthorization();

        await using var provider = services.BuildServiceProvider();
        var auth = provider.GetRequiredService<IAuthorizationService>();
        var user = TestPrincipals.With("alice", permissions: ["orders:read"]);

        var granted = await auth.AuthorizeAsync(
            user, resource: null, OrionGrantRequirement.ForPermission("orders:read"));
        var denied = await auth.AuthorizeAsync(
            user, resource: null, OrionGrantRequirement.ForPermission("orders:write"));

        Assert.True(granted.Succeeded);
        Assert.False(denied.Succeeded);
    }

    [Fact]
    public void handler_is_registered_scoped_so_it_does_not_capture_scoped_dependencies()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOrionGrantAuthorization();

        var descriptor = Assert.Single(
            services,
            d => d.ServiceType == typeof(IAuthorizationHandler)
                && d.ImplementationType == typeof(OrionGrantAuthorizationHandler));

        Assert.Equal(ServiceLifetime.Scoped, descriptor.Lifetime);
    }

    [Fact]
    public async Task scoped_principal_resolver_is_resolved_per_request_under_validate_scopes()
    {
        // A custom scoped resolver (the realistic case: it consults a scoped store). The container is
        // built with ValidateScopes so a captive dependency - a singleton handler holding a scoped
        // resolver - throws when the handler is resolved. A correctly scoped handler resolves the
        // scoped resolver fresh in each scope. (ValidateOnBuild is intentionally off: AddAuthorization
        // registers AuthorizationPolicyCache, which needs routing's EndpointDataSource that a bare
        // ServiceCollection has no host to provide; that is orthogonal to the captive-dependency check.)
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOrionGrantAuthorization();
        services.AddScoped<IGrantPrincipalResolver, ScopedCountingResolver>();

        await using var provider = services.BuildServiceProvider(
            new ServiceProviderOptions { ValidateScopes = true });

        var user = TestPrincipals.With("alice", permissions: ["orders:read"]);

        await using (var scope = provider.CreateAsyncScope())
        {
            var auth = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
            var result = await auth.AuthorizeAsync(
                user, resource: null, OrionGrantRequirement.ForPermission("orders:read"));
            Assert.True(result.Succeeded);
        }

        await using (var scope = provider.CreateAsyncScope())
        {
            var auth = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
            var result = await auth.AuthorizeAsync(
                user, resource: null, OrionGrantRequirement.ForPermission("orders:read"));
            Assert.True(result.Succeeded);
        }

        // One distinct resolver instance per scope: two scopes, two instances.
        Assert.Equal(2, ScopedCountingResolver.InstanceCount);
    }

    [Fact]
    public async Task resource_attributes_reach_an_abac_policy_condition()
    {
        // The policy grants only when its ABAC condition sees the resource owner matching a fixed id.
        // The condition can observe the resource only if the handler surfaces the ResourceContext to
        // AuthorizePolicy as attributes; with no resource it would deny.
        var auth = BuildAuthorizationService(b => b.AddPolicy(
            "orders.read-owned",
            PolicyMode.RequireAll,
            attributes => attributes.Resource?.OwnerId == "tenant-7",
            "orders:read"));

        var user = TestPrincipals.With("alice", permissions: ["orders:read"]);

        var matching = await auth.AuthorizeAsync(
            user,
            new OrionGrantResource(new ResourceContext(ownerId: "tenant-7")),
            OrionGrantRequirement.ForPolicy("orders.read-owned"));

        var nonMatching = await auth.AuthorizeAsync(
            user,
            new OrionGrantResource(new ResourceContext(ownerId: "tenant-9")),
            OrionGrantRequirement.ForPolicy("orders.read-owned"));

        var noResource = await auth.AuthorizeAsync(
            user, resource: null, OrionGrantRequirement.ForPolicy("orders.read-owned"));

        Assert.True(matching.Succeeded);
        Assert.False(nonMatching.Succeeded);
        Assert.False(noResource.Succeeded);

        var reason = Assert.IsType<OrionGrantAuthorizationFailureReason>(
            Assert.Single(nonMatching.Failure!.FailureReasons));
        Assert.Equal(DenialKind.ConditionUnmet, reason.Denial!.Kind);
        Assert.Equal("orders.read-owned", reason.Denial.PolicyName);
    }

    [Fact]
    public async Task unsupported_resource_type_is_denied_fail_closed()
    {
        // A resource the integration does not understand (a plain object) must deny, not fall through
        // to a weaker permission-only check that would have granted on the held permission alone.
        var auth = BuildAuthorizationService();
        var user = TestPrincipals.With("alice", permissions: ["orders:read"]);

        var result = await auth.AuthorizeAsync(
            user,
            resource: new object(),
            OrionGrantRequirement.ForPermission("orders:read"));

        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task unsupported_resource_type_is_denied_for_a_policy_requirement_too()
    {
        var auth = BuildAuthorizationService(b => b.AddPolicy(
            "orders.manage", PolicyMode.RequireAll, "orders:read"));
        var user = TestPrincipals.With("alice", permissions: ["orders:read"]);

        var result = await auth.AuthorizeAsync(
            user,
            resource: new object(),
            OrionGrantRequirement.ForPolicy("orders.manage"));

        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task policy_denial_reports_a_policy_reason_not_missing_permission()
    {
        // An unresolved principal under a policy requirement must not be labeled MissingPermission;
        // the requirement is a policy, so the denial kind reflects the policy not being satisfied.
        var auth = BuildAuthorizationService(b => b.AddPolicy(
            "orders.manage", PolicyMode.RequireAll, "orders:read"));

        var result = await auth.AuthorizeAsync(
            TestPrincipals.Anonymous(),
            resource: null,
            OrionGrantRequirement.ForPolicy("orders.manage"));

        Assert.False(result.Succeeded);
        var reason = Assert.IsType<OrionGrantAuthorizationFailureReason>(
            Assert.Single(result.Failure!.FailureReasons));
        Assert.NotEqual(DenialKind.MissingPermission, reason.Denial!.Kind);
        Assert.Equal(DenialKind.PolicyRequirementUnmet, reason.Denial.Kind);
        Assert.Equal("orders.manage", reason.Denial.PolicyName);
    }

    [Fact]
    public void invalid_claim_type_options_throw_at_startup()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOrionGrantAuthorization();
        services.Configure<OrionGrantClaimsOptions>(o => o.SubjectClaimType = "");

        // ValidateOnStart surfaces the failure when the option is first materialized; resolving the
        // resolver (which reads OrionGrantClaimsOptions) forces that materialization.
        using var provider = services.BuildServiceProvider();

        var ex = Assert.Throws<OptionsValidationException>(
            provider.GetRequiredService<IGrantPrincipalResolver>);
        Assert.Contains("SubjectClaimType", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void null_policy_name_prefix_options_throw_at_startup()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOrionGrantAuthorization();
        services.Configure<OrionGrantPolicyNameOptions>(o => o.PermissionPrefix = null!);

        using var provider = services.BuildServiceProvider();
        var policyNameOptions = provider.GetRequiredService<IOptions<OrionGrantPolicyNameOptions>>();

        var ex = Assert.Throws<OptionsValidationException>(() => _ = policyNameOptions.Value);
        Assert.Contains("PermissionPrefix", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task empty_subject_claim_type_still_falls_back_to_the_sub_claim()
    {
        // Even with no usable configured subject claim type, the standard JWT 'sub' claim must still
        // be honored as the floor identity source rather than bypassed.
        var resolver = new ClaimsGrantPrincipalResolver(
            Options.Create(new OrionGrantClaimsOptions { SubjectClaimType = "" }));

        var user = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("sub", "service-account")],
            TestPrincipals.AuthenticationType));

        var principal = await resolver.ResolveAsync(user);

        Assert.NotNull(principal);
        Assert.Equal("service-account", principal!.Subject);
    }

    private static IAuthorizationService BuildAuthorizationService(Action<OrionGrantBuilder>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOrionGrantAuthorization(configure);
        return services.BuildServiceProvider().GetRequiredService<IAuthorizationService>();
    }

    /// <summary>
    /// A scoped resolver that counts how many instances are constructed, used to prove the handler
    /// resolves its dependency per scope rather than capturing a single instance.
    /// </summary>
    private sealed class ScopedCountingResolver : IGrantPrincipalResolver
    {
        private static int instanceCount;

        public ScopedCountingResolver() => Interlocked.Increment(ref instanceCount);

        public static int InstanceCount => Volatile.Read(ref instanceCount);

        public ValueTask<GrantPrincipal?> ResolveAsync(
            ClaimsPrincipal user,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(user);
            var subject = user.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(subject))
            {
                return new ValueTask<GrantPrincipal?>((GrantPrincipal?)null);
            }

            var permissions = user.FindAll("permission").Select(c => c.Value).ToArray();
            return new ValueTask<GrantPrincipal?>(new GrantPrincipal
            {
                Subject = subject,
                Permissions = permissions,
            });
        }
    }
}

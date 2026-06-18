namespace Moongazing.OrionGrant.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.Extensions.DependencyInjection;

using Moongazing.OrionGrant;
using Moongazing.OrionGrant.Diagnostics;
using Moongazing.OrionGrant.Permissions;
using Moongazing.OrionGrant.Policies;

using Xunit;

/// <summary>
/// Coverage of <see cref="OrionGrantServiceCollectionExtensions.AddOrionGrant"/>: every component
/// resolves, lifetimes are singleton, the registrations are idempotent (TryAdd), a caller-supplied
/// implementation wins, and argument validation.
/// </summary>
public sealed class OrionGrantServiceCollectionTests
{
    [Fact]
    public void AddOrionGrant_resolves_every_registered_component()
    {
        var services = new ServiceCollection();
        services.AddOrionGrant();

        using var provider = services.BuildServiceProvider();

        Assert.NotNull(provider.GetService<IGrantAuthorizer>());
        Assert.NotNull(provider.GetService<RoleRegistry>());
        Assert.NotNull(provider.GetService<PolicyRegistry>());
        Assert.NotNull(provider.GetService<GrantDiagnostics>());
    }

    [Fact]
    public void AddOrionGrant_registers_the_authorizer_as_a_singleton()
    {
        var services = new ServiceCollection();
        services.AddOrionGrant();

        using var provider = services.BuildServiceProvider();
        var first = provider.GetRequiredService<IGrantAuthorizer>();
        var second = provider.GetRequiredService<IGrantAuthorizer>();

        Assert.Same(first, second);
    }

    [Fact]
    public void AddOrionGrant_returns_the_same_service_collection_for_chaining()
    {
        var services = new ServiceCollection();

        var returned = services.AddOrionGrant();

        Assert.Same(services, returned);
    }

    [Fact]
    public void AddOrionGrant_default_registration_denies_an_unconfigured_principal()
    {
        var services = new ServiceCollection();
        services.AddOrionGrant();

        using var provider = services.BuildServiceProvider();
        var authorizer = provider.GetRequiredService<IGrantAuthorizer>();
        var principal = new GrantPrincipal { Subject = "u1" };

        Assert.False(authorizer.Authorize(principal, "orders:read").IsGranted);
    }

    [Fact]
    public void AddOrionGrant_wires_configured_roles_and_policies()
    {
        var services = new ServiceCollection();
        services.AddOrionGrant(b => b
            .AddRole("admin", "*")
            .AddPolicy("anything", PolicyMode.RequireAll, "orders:write"));

        using var provider = services.BuildServiceProvider();
        var authorizer = provider.GetRequiredService<IGrantAuthorizer>();
        var admin = new GrantPrincipal { Subject = "u1", Roles = ["admin"] };

        Assert.True(authorizer.Authorize(admin, "orders:write").IsGranted);
        Assert.True(authorizer.AuthorizePolicy(admin, "anything").IsGranted);
    }

    [Fact]
    public void AddOrionGrant_is_idempotent_and_keeps_a_preexisting_authorizer()
    {
        var sentinel = new StubAuthorizer();
        var services = new ServiceCollection();
        services.AddSingleton<IGrantAuthorizer>(sentinel);

        // TryAddSingleton must not overwrite the caller's registration.
        services.AddOrionGrant(b => b.AddRole("admin", "*"));

        using var provider = services.BuildServiceProvider();
        Assert.Same(sentinel, provider.GetRequiredService<IGrantAuthorizer>());
    }

    [Fact]
    public void AddOrionGrant_called_twice_keeps_the_first_configuration()
    {
        var services = new ServiceCollection();
        services.AddOrionGrant(b => b.AddRole("admin", "*"));

        // Second call's builder is discarded because the registries are already registered.
        services.AddOrionGrant(b => b.AddRole("admin", "nothing:useful"));

        using var provider = services.BuildServiceProvider();
        var authorizer = provider.GetRequiredService<IGrantAuthorizer>();
        var admin = new GrantPrincipal { Subject = "u1", Roles = ["admin"] };

        Assert.True(authorizer.Authorize(admin, "orders:write").IsGranted);
    }

    [Fact]
    public void AddOrionGrant_throws_when_services_is_null()
    {
        Assert.Throws<ArgumentNullException>(() => ((IServiceCollection)null!).AddOrionGrant());
    }

    private sealed class StubAuthorizer : IGrantAuthorizer
    {
        public AuthorizationResult Authorize(GrantPrincipal principal, string requiredPermission) =>
            AuthorizationResult.Granted;

        public AuthorizationResult AuthorizePolicy(GrantPrincipal principal, string policyName) =>
            AuthorizationResult.Granted;

        public IReadOnlySet<string> EffectivePermissions(GrantPrincipal principal) =>
            new HashSet<string>();
    }
}

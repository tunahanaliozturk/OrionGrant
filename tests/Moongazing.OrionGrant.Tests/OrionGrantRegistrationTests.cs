namespace Moongazing.OrionGrant.Tests;

using Microsoft.Extensions.DependencyInjection;

using Moongazing.OrionGrant;
using Moongazing.OrionGrant.Policies;

using Xunit;

public sealed class OrionGrantRegistrationTests
{
    [Fact]
    public void AddOrionGrant_resolves_an_authorizer()
    {
        var services = new ServiceCollection();
        services.AddOrionGrant();

        using var provider = services.BuildServiceProvider();
        Assert.NotNull(provider.GetService<IGrantAuthorizer>());
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
}

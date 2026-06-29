namespace Moongazing.OrionGrant.AspNetCore.Tests;

using System.Security.Claims;

using Microsoft.Extensions.Options;

using Xunit;

/// <summary>
/// Verifies the default claims-to-grants mapping, including the configured claim types and the
/// unauthenticated and missing-subject cases that must resolve to null.
/// </summary>
public sealed class ClaimsGrantPrincipalResolverTests
{
    private static ClaimsGrantPrincipalResolver Resolver(OrionGrantClaimsOptions? options = null) =>
        new(Options.Create(options ?? new OrionGrantClaimsOptions()));

    [Fact]
    public async Task maps_subject_roles_permissions_and_denies_from_claims()
    {
        var user = TestPrincipals.With(
            "alice",
            permissions: ["orders:read", "orders:write"],
            roles: ["operator"],
            denies: ["billing:*"]);

        var principal = await Resolver().ResolveAsync(user);

        Assert.NotNull(principal);
        Assert.Equal("alice", principal!.Subject);
        Assert.Equal(["operator"], principal.Roles);
        Assert.Equal(["orders:read", "orders:write"], principal.Permissions);
        Assert.Equal(["billing:*"], principal.Denies);
    }

    [Fact]
    public async Task unauthenticated_user_resolves_to_null()
    {
        var principal = await Resolver().ResolveAsync(TestPrincipals.Anonymous());

        Assert.Null(principal);
    }

    [Fact]
    public async Task authenticated_user_without_subject_claim_resolves_to_null()
    {
        var user = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("permission", "orders:read")],
            TestPrincipals.AuthenticationType));

        var principal = await Resolver().ResolveAsync(user);

        Assert.Null(principal);
    }

    [Fact]
    public async Task falls_back_to_the_jwt_sub_claim_for_the_subject()
    {
        var user = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("sub", "service-account")],
            TestPrincipals.AuthenticationType));

        var principal = await Resolver().ResolveAsync(user);

        Assert.NotNull(principal);
        Assert.Equal("service-account", principal!.Subject);
    }

    [Fact]
    public async Task honors_custom_claim_types()
    {
        var options = new OrionGrantClaimsOptions
        {
            SubjectClaimType = "uid",
            PermissionClaimType = "scope",
        };
        var user = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("uid", "alice"), new Claim("scope", "orders:read")],
            TestPrincipals.AuthenticationType));

        var principal = await Resolver(options).ResolveAsync(user);

        Assert.NotNull(principal);
        Assert.Equal("alice", principal!.Subject);
        Assert.Equal(["orders:read"], principal.Permissions);
    }
}

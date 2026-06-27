namespace Moongazing.OrionGrant.Tests;

using System;

using Moongazing.OrionGrant;
using Moongazing.OrionGrant.Diagnostics;
using Moongazing.OrionGrant.Policies;

using Xunit;

/// <summary>
/// Coverage of explicit denies (deny-overrides). A deny pattern on the principal removes a matching
/// permission from an otherwise-granted set, across the single-permission, resource, and policy
/// paths, and the denial reason reflects the explicit deny with the pattern that blocked it. A
/// principal with no denies behaves exactly as in 0.3.0.
/// </summary>
public sealed class ExplicitDenyTests
{
    private static GrantAuthorizer Build(
        GrantDiagnostics diagnostics,
        Action<OrionGrantBuilder>? configure = null)
    {
        var builder = new OrionGrantBuilder();
        configure?.Invoke(builder);
        return new GrantAuthorizer(builder.BuildRoles(), builder.BuildPolicies(), diagnostics);
    }

    [Fact]
    public void Deny_overrides_a_direct_allow()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal
        {
            Subject = "u1",
            Permissions = ["orders:read"],
            Denies = ["orders:read"],
        };

        var result = authorizer.Authorize(principal, "orders:read");

        Assert.False(result.IsGranted);
        Assert.NotNull(result.Denial);
        Assert.Equal(DenialKind.ExplicitDeny, result.Denial!.Kind);
        Assert.Equal("orders:read", result.Denial.Permission);
        Assert.Equal("orders:read", result.Denial.DenyPattern);
    }

    [Fact]
    public void Deny_overrides_a_role_granted_allow()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b.AddRole("reader", "orders:read", "orders:write"));
        var principal = new GrantPrincipal
        {
            Subject = "u1",
            Roles = ["reader"],
            Denies = ["orders:write"],
        };

        // The allow survives for read but the deny removes write.
        Assert.True(authorizer.Authorize(principal, "orders:read").IsGranted);

        var denied = authorizer.Authorize(principal, "orders:write");
        Assert.False(denied.IsGranted);
        Assert.Equal(DenialKind.ExplicitDeny, denied.Denial!.Kind);
        Assert.Equal("orders:write", denied.Denial.DenyPattern);
    }

    [Fact]
    public void A_wildcard_deny_overrides_a_wildcard_allow()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal
        {
            Subject = "u1",
            Permissions = ["orders:*"],
            Denies = ["orders:*"],
        };

        var result = authorizer.Authorize(principal, "orders:read:detail");

        Assert.False(result.IsGranted);
        Assert.Equal(DenialKind.ExplicitDeny, result.Denial!.Kind);
        Assert.Equal("orders:*", result.Denial.DenyPattern);
    }

    [Fact]
    public void Deny_does_not_affect_permissions_it_does_not_cover()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal
        {
            Subject = "u1",
            Permissions = ["orders:read", "billing:read"],
            Denies = ["billing:read"],
        };

        Assert.True(authorizer.Authorize(principal, "orders:read").IsGranted);
        Assert.False(authorizer.Authorize(principal, "billing:read").IsGranted);
    }

    [Fact]
    public void Deny_overrides_ownership_on_the_resource_path()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal
        {
            Subject = "u1",
            Permissions = ["accounts:read"],
            Denies = ["accounts:read"],
        };

        // The principal owns the resource and holds the permission, yet the deny wins.
        var result = authorizer.Authorize(
            principal,
            "accounts:read",
            ResourceContext.OwnedBy("u1"));

        Assert.False(result.IsGranted);
        Assert.Equal(DenialKind.ExplicitDeny, result.Denial!.Kind);
        Assert.Equal("accounts:read", result.Denial.DenyPattern);
    }

    [Fact]
    public void Deny_overrides_root_wildcard_elevation_on_the_resource_path()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal
        {
            Subject = "admin",
            Permissions = ["*"],
            Denies = ["accounts:delete"],
        };

        // A root grant would normally bypass ownership, but the carve-out removes the permission.
        var result = authorizer.Authorize(
            principal,
            "accounts:delete",
            ResourceContext.OwnedBy("someone-else"));

        Assert.False(result.IsGranted);
        Assert.Equal(DenialKind.ExplicitDeny, result.Denial!.Kind);
    }

    [Fact]
    public void Deny_on_a_configured_elevated_permission_strips_the_bypass_and_ownership_governs()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        // The principal holds the base permission and an elevated "any" grant, but the elevated grant
        // is explicitly denied. The base permission is NOT denied, so deny-overrides must apply to the
        // elevated grant itself: the bypass is removed and ownership governs, which fails here.
        var principal = new GrantPrincipal
        {
            Subject = "support-agent",
            Permissions = ["accounts:read", "accounts:read:any"],
            Denies = ["accounts:read:any"],
        };
        var resource = ResourceContext.OwnedBy("some-customer");
        var options = new ResourceAuthorizationOptions
        {
            ElevatedPermissions = ["accounts:read:any"],
        };

        var result = authorizer.Authorize(principal, "accounts:read", resource, options);

        Assert.False(result.IsGranted);
        // The required permission was held and not denied, so the denial is ownership, not the deny:
        // the deny only stripped the elevated bypass.
        Assert.Equal(DenialKind.ResourceOwnership, result.Denial!.Kind);
    }

    [Fact]
    public void Deny_on_the_root_wildcard_strips_elevation_for_an_unrelated_required_permission()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        // The root grant is the only thing that both grants the required permission and elevates. A
        // deny on the root wildcard itself must remove the elevated bypass; ownership then governs.
        var principal = new GrantPrincipal
        {
            Subject = "admin",
            Permissions = ["*"],
            Denies = ["*"],
        };
        var resource = ResourceContext.OwnedBy("someone-else");

        // The base permission gate also fails once the deny on "*" covers it, so the principal is
        // denied. Either way no elevated grant survives the deny.
        var result = authorizer.Authorize(principal, "accounts:read", resource);

        Assert.False(result.IsGranted);
        Assert.Equal(DenialKind.ExplicitDeny, result.Denial!.Kind);
    }

    [Fact]
    public void A_non_denied_elevated_grant_still_authorizes_on_the_resource_path()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        // Regression guard: an elevated grant that is NOT denied must continue to bypass ownership.
        var principal = new GrantPrincipal
        {
            Subject = "support-agent",
            Permissions = ["accounts:read", "accounts:read:any"],
            Denies = ["billing:write"],
        };
        var resource = ResourceContext.OwnedBy("some-customer");
        var options = new ResourceAuthorizationOptions
        {
            ElevatedPermissions = ["accounts:read:any"],
        };

        var result = authorizer.Authorize(principal, "accounts:read", resource, options);

        Assert.True(result.IsGranted);
        Assert.Null(result.Denial);
    }

    [Fact]
    public void A_non_denied_root_wildcard_still_bypasses_ownership_on_the_resource_path()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        // Regression guard: a root grant with an unrelated carve-out must still elevate.
        var principal = new GrantPrincipal
        {
            Subject = "admin",
            Permissions = ["*"],
            Denies = ["accounts:delete"],
        };
        var resource = ResourceContext.OwnedBy("someone-else");

        var result = authorizer.Authorize(principal, "accounts:read", resource);

        Assert.True(result.IsGranted);
        Assert.Null(result.Denial);
    }

    [Fact]
    public void Deny_overrides_a_require_all_policy_permission()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b
            .AddPolicy("orders.manage", PolicyMode.RequireAll, "orders:read", "orders:write"));
        var principal = new GrantPrincipal
        {
            Subject = "u1",
            Permissions = ["orders:read", "orders:write"],
            Denies = ["orders:write"],
        };

        var result = authorizer.AuthorizePolicy(principal, "orders.manage");

        Assert.False(result.IsGranted);
        Assert.Equal(DenialKind.ExplicitDeny, result.Denial!.Kind);
        Assert.Equal("orders:write", result.Denial.Permission);
        Assert.Equal("orders:write", result.Denial.DenyPattern);
    }

    [Fact]
    public void Deny_removes_a_require_any_policy_alternative()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b
            .AddPolicy("orders.touch", PolicyMode.RequireAny, "orders:read", "orders:write"));
        var principal = new GrantPrincipal
        {
            Subject = "u1",
            Permissions = ["orders:read"],
            Denies = ["orders:read"],
        };

        // The only held alternative is denied, so the any-of policy is unmet.
        var result = authorizer.AuthorizePolicy(principal, "orders.touch");

        Assert.False(result.IsGranted);
        Assert.Equal(DenialKind.PolicyRequirementUnmet, result.Denial!.Kind);
    }

    [Fact]
    public void Require_any_still_grants_through_a_non_denied_alternative()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b
            .AddPolicy("orders.touch", PolicyMode.RequireAny, "orders:read", "orders:write"));
        var principal = new GrantPrincipal
        {
            Subject = "u1",
            Permissions = ["orders:read", "orders:write"],
            Denies = ["orders:read"],
        };

        // read is denied but write still satisfies the any-of policy.
        Assert.True(authorizer.AuthorizePolicy(principal, "orders.touch").IsGranted);
    }

    [Fact]
    public void A_principal_with_no_denies_behaves_as_before()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:read"] };

        var result = authorizer.Authorize(principal, "orders:read");

        Assert.True(result.IsGranted);
        Assert.Null(result.Denial);
    }

    [Fact]
    public void An_empty_deny_string_is_ignored()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal
        {
            Subject = "u1",
            Permissions = ["orders:read"],
            Denies = [""],
        };

        // An empty deny entry must not block anything.
        Assert.True(authorizer.Authorize(principal, "orders:read").IsGranted);
    }
}

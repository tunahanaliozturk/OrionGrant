namespace Moongazing.OrionGrant.Demo;

/// <summary>
/// Resource / ownership-aware (object-level) authorization. Holding the permission is necessary but
/// not sufficient: the principal must also own the resource or hold an elevated grant. This is the
/// IDOR-resistant path - two callers can both hold <c>accounts:read</c> yet only read their own row.
/// </summary>
internal static class ResourceOwnershipDemo
{
    public static void Run(IGrantAuthorizer authorizer)
    {
        DemoConsole.Section("5. Resource / ownership-aware authorization (object-level)");
        DemoConsole.Blank();

        // The resource being accessed: account-42, owned by user u1. The owner id is what the
        // authorizer compares against the principal subject.
        var account = new ResourceContext(ownerId: "u1", resourceType: "account", resourceId: "42");

        // Owner: u1 holds accounts:read AND owns the resource, so the read is granted.
        var owner = new GrantPrincipal { Subject = "u1", Permissions = ["accounts:read"] };
        DemoConsole.Line($"Principal '{owner.Subject}' holds 'accounts:read' and owns account 42");
        DemoConsole.Decision("accounts:read on account 42", authorizer.Authorize(owner, "accounts:read", account));

        DemoConsole.Blank();

        // Non-owner: u2 holds the very same permission but does not own the resource and has no
        // elevated grant, so the read is denied even though the permission check passes.
        var stranger = new GrantPrincipal { Subject = "u2", Permissions = ["accounts:read"] };
        DemoConsole.Line($"Principal '{stranger.Subject}' holds 'accounts:read' but does not own account 42");
        DemoConsole.Decision("accounts:read on account 42", authorizer.Authorize(stranger, "accounts:read", account));

        DemoConsole.Blank();

        // Elevated bypass: a support principal holding the configured elevated permission reads any
        // account it does not own. The "owner OR elevated" set is supplied per call via options.
        var options = new ResourceAuthorizationOptions { ElevatedPermissions = ["accounts:read:any"] };
        var support = new GrantPrincipal { Subject = "svc-support", Permissions = ["accounts:read", "accounts:read:any"] };
        DemoConsole.Line($"Principal '{support.Subject}' holds the elevated 'accounts:read:any' and bypasses ownership");
        DemoConsole.Decision("accounts:read on account 42", authorizer.Authorize(support, "accounts:read", account, options));

        DemoConsole.Blank();

        // Root bypass: a principal holding the root '*' grant bypasses ownership with no per-call
        // configuration, because TreatRootWildcardAsElevated is on by default.
        var admin = new GrantPrincipal { Subject = "svc-admin", Permissions = ["*"] };
        DemoConsole.Line($"Principal '{admin.Subject}' holds the root '*' grant and bypasses ownership by default");
        DemoConsole.Decision("accounts:read on account 42", authorizer.Authorize(admin, "accounts:read", account));
    }
}

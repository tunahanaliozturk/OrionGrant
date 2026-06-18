namespace Moongazing.OrionGrant.Demo;

/// <summary>
/// A single-permission authorize check, allowed vs denied, modelling what an endpoint would do:
/// build a principal from the caller's roles and scopes, then gate on a required permission.
/// </summary>
internal static class AuthorizeAllowedDeniedDemo
{
    public static void Run(IGrantAuthorizer authorizer)
    {
        DemoConsole.Section("4. Authorize a single permission: allowed vs denied");
        DemoConsole.Blank();

        // Allowed: the manager's orders:* covers the required orders:write.
        var manager = new GrantPrincipal { Subject = "svc-manager", Roles = ["orders.manager"] };
        DemoConsole.Line($"Principal '{manager.Subject}' requires 'orders:write'");
        DemoConsole.Decision("orders:write", authorizer.Authorize(manager, "orders:write"));

        DemoConsole.Blank();

        // Denied: the auditor only holds read scopes, so a write request is refused with a reason.
        var auditor = new GrantPrincipal { Subject = "svc-auditor", Roles = ["auditor"] };
        DemoConsole.Line($"Principal '{auditor.Subject}' requires 'orders:write'");
        DemoConsole.Decision("orders:write", authorizer.Authorize(auditor, "orders:write"));

        DemoConsole.Blank();

        // A principal built straight from issued scopes (for example, OrionLedger API-key scopes).
        var apiCaller = new GrantPrincipal
        {
            Subject = "api-key-7f3",
            Permissions = ["billing:read", "billing:write"],
        };
        DemoConsole.Line($"Principal '{apiCaller.Subject}' (direct scopes: billing:read, billing:write)");
        DemoConsole.Decision("billing:write", authorizer.Authorize(apiCaller, "billing:write"));
        DemoConsole.Decision("orders:read", authorizer.Authorize(apiCaller, "orders:read"));
    }
}

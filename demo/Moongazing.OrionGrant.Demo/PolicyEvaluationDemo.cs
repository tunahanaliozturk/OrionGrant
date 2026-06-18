namespace Moongazing.OrionGrant.Demo;

/// <summary>
/// Evaluates named policies in both modes. RequireAll needs every listed permission; RequireAny
/// needs at least one. Each listed permission is checked through the same wildcard matcher, so a
/// principal holding 'orders:*' satisfies a policy that lists 'orders:read' and 'orders:write'.
/// </summary>
internal static class PolicyEvaluationDemo
{
    public static void Run(IGrantAuthorizer authorizer)
    {
        DemoConsole.Section("3. Policy evaluation: RequireAll and RequireAny");
        DemoConsole.Line("Policies: 'orders.manage' = RequireAll(orders:read, orders:write),");
        DemoConsole.Line("          'orders.touch'  = RequireAny(orders:read, orders:write).");
        DemoConsole.Blank();

        // A read-only auditor: satisfies RequireAny via orders:read, fails RequireAll (no write).
        var auditor = new GrantPrincipal { Subject = "svc-auditor", Roles = ["auditor"] };
        DemoConsole.Line($"Principal '{auditor.Subject}' (auditor: orders:read, billing:read)");
        DemoConsole.Decision("orders.manage", authorizer.AuthorizePolicy(auditor, "orders.manage"));
        DemoConsole.Decision("orders.touch", authorizer.AuthorizePolicy(auditor, "orders.touch"));

        DemoConsole.Blank();

        // A manager holding orders:* satisfies both, because the wildcard covers read and write.
        var manager = new GrantPrincipal { Subject = "svc-manager", Roles = ["orders.manager"] };
        DemoConsole.Line($"Principal '{manager.Subject}' (orders.manager: orders:*)");
        DemoConsole.Decision("orders.manage", authorizer.AuthorizePolicy(manager, "orders.manage"));
        DemoConsole.Decision("orders.touch", authorizer.AuthorizePolicy(manager, "orders.touch"));

        DemoConsole.Blank();

        // An unknown policy name is denied with a reason rather than throwing.
        DemoConsole.Line("Unknown policy names are denied, not thrown:");
        DemoConsole.Decision("orders.delete (undefined)", authorizer.AuthorizePolicy(manager, "orders.delete"));
    }
}

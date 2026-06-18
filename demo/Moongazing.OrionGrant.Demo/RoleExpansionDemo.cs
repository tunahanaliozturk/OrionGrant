namespace Moongazing.OrionGrant.Demo;

/// <summary>
/// Shows how the authorizer expands a principal's roles into an effective permission set and unions
/// that with the principal's direct grants. Unknown roles contribute nothing.
/// </summary>
internal static class RoleExpansionDemo
{
    public static void Run(IGrantAuthorizer authorizer)
    {
        DemoConsole.Section("2. Role expansion into effective permissions");
        DemoConsole.Line("Roles configured: 'orders.manager' => orders:*, 'auditor' => orders:read, billing:read.");
        DemoConsole.Blank();

        // Holds a known role plus a direct grant and an unknown role that should be ignored.
        var manager = new GrantPrincipal
        {
            Subject = "svc-manager",
            Roles = ["orders.manager", "ghost-role"],
            Permissions = ["billing:read"],
        };

        var effective = authorizer.EffectivePermissions(manager);
        DemoConsole.Line($"Principal '{manager.Subject}'");
        DemoConsole.Line($"  roles       : {string.Join(", ", manager.Roles)}");
        DemoConsole.Line($"  direct perms: {string.Join(", ", manager.Permissions)}");
        DemoConsole.Line($"  effective   : {string.Join(", ", effective.OrderBy(p => p, StringComparer.Ordinal))}");
        DemoConsole.Line("  (the unknown 'ghost-role' added nothing)");

        DemoConsole.Blank();

        var auditor = new GrantPrincipal
        {
            Subject = "svc-auditor",
            Roles = ["auditor"],
        };
        var auditorEffective = authorizer.EffectivePermissions(auditor);
        DemoConsole.Line($"Principal '{auditor.Subject}'");
        DemoConsole.Line($"  roles       : {string.Join(", ", auditor.Roles)}");
        DemoConsole.Line($"  effective   : {string.Join(", ", auditorEffective.OrderBy(p => p, StringComparer.Ordinal))}");
    }
}

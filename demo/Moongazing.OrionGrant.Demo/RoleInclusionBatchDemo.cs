namespace Moongazing.OrionGrant.Demo;

using Microsoft.Extensions.DependencyInjection;

using Moongazing.OrionGrant.Policies;

/// <summary>
/// Tours the 0.3.0 additions: role-to-role inclusion (a role composing other roles, permissions
/// resolving transitively), structured denial reasons (branching on the cause of a denial), and
/// batch checks (several requirements for one principal in a single call). Uses its own authorizer
/// so the inclusion graph is self-contained.
/// </summary>
internal static class RoleInclusionBatchDemo
{
    public static void Run()
    {
        DemoConsole.Section("6. Role inclusion, structured denial, and batch checks (0.3.0)");

        // editor includes reader; admin includes editor. Permissions compose transitively, so admin
        // ends up with reader's and editor's permissions plus its own.
        var services = new ServiceCollection();
        services.AddOrionGrant(grant => grant
            .AddRole("reader", "orders:read")
            .AddRole("editor", "orders:write")
            .AddRole("admin", "orders:delete")
            .IncludeRole("editor", "reader")
            .IncludeRole("admin", "editor")
            .AddPolicy("orders.manage", PolicyMode.RequireAll, "orders:read", "orders:write")
            .AddPolicy("orders.purge", PolicyMode.RequireAll, "orders:delete", "orders:audit"));

        using var provider = services.BuildServiceProvider();
        var authorizer = provider.GetRequiredService<IGrantAuthorizer>();

        var admin = new GrantPrincipal { Subject = "svc-admin", Roles = ["admin"] };

        DemoConsole.Line("Roles: reader => orders:read; editor => orders:write (includes reader);");
        DemoConsole.Line("       admin  => orders:delete (includes editor).");
        DemoConsole.Line($"Effective set for '{admin.Subject}' (admin): " +
            $"{string.Join(", ", authorizer.EffectivePermissions(admin).OrderBy(p => p, StringComparer.Ordinal))}");
        DemoConsole.Line("  (orders:read and orders:write arrived transitively through inclusion)");

        DemoConsole.Blank();
        DemoConsole.Line("Batch permission check for the admin principal:");
        var permissionBatch = authorizer.AuthorizeAll(
            admin, ["orders:read", "orders:write", "orders:delete", "billing:read"]);
        foreach (var entry in permissionBatch)
        {
            DemoConsole.Decision(entry.Requirement, entry.Result);
        }

        DemoConsole.Blank();
        DemoConsole.Line("Batch policy check, then branching on the structured denial cause:");
        var policyBatch = authorizer.AuthorizeAllPolicies(admin, ["orders.manage", "orders.purge", "ghost"]);
        foreach (var entry in policyBatch)
        {
            DemoConsole.Decision(entry.Requirement, entry.Result);
            if (entry.Result.Denial is { } denial)
            {
                DemoConsole.Line($"          cause: kind={denial.Kind}" +
                    (denial.PolicyMode is { } mode ? $", mode={mode}" : string.Empty) +
                    (denial.Permission is { } perm ? $", missing={perm}" : string.Empty));
            }
        }
    }
}

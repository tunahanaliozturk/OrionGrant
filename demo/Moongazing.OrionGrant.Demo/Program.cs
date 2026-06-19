namespace Moongazing.OrionGrant.Demo;

using Microsoft.Extensions.DependencyInjection;

using Moongazing.OrionGrant;
using Moongazing.OrionGrant.Policies;

/// <summary>
/// Runnable tour of OrionGrant: wildcard permission matching, role expansion into an effective set,
/// RequireAll / RequireAny policy evaluation, and a single-permission authorize allowed vs denied.
/// Everything goes through the real <see cref="IGrantAuthorizer"/> resolved from DI via AddOrionGrant.
/// </summary>
internal static class Program
{
    private static void Main()
    {
        DemoConsole.Line("OrionGrant demo - permission and policy authorization for .NET");

        // Register the real authorizer exactly as an application would, with roles and policies
        // resolved once at startup into immutable registries.
        var services = new ServiceCollection();
        services.AddOrionGrant(grant => grant
            .AddRole("orders.manager", "orders:*")
            .AddRole("auditor", "orders:read", "billing:read")
            .AddPolicy("orders.manage", PolicyMode.RequireAll, "orders:read", "orders:write")
            .AddPolicy("orders.touch", PolicyMode.RequireAny, "orders:read", "orders:write"));

        using var provider = services.BuildServiceProvider();
        var authorizer = provider.GetRequiredService<IGrantAuthorizer>();

        // 1. Pure matcher, no container needed.
        WildcardMatchingDemo.Run();

        // 2-5. Drive the real authorizer resolved above.
        RoleExpansionDemo.Run(authorizer);
        PolicyEvaluationDemo.Run(authorizer);
        AuthorizeAllowedDeniedDemo.Run(authorizer);
        ResourceOwnershipDemo.Run(authorizer);

        DemoConsole.Blank();
        DemoConsole.Line("Demo complete.");
    }
}

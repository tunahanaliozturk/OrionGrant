namespace Moongazing.OrionGrant.Demo;

using Moongazing.OrionGrant.Permissions;

/// <summary>
/// Drives the pure <see cref="PermissionMatcher"/> directly, with no DI container and no authorizer,
/// to show exactly how colon-scoped wildcards expand. These are the same rules the authorizer uses.
/// </summary>
internal static class WildcardMatchingDemo
{
    public static void Run()
    {
        DemoConsole.Section("1. Wildcard permission matching (PermissionMatcher, pure)");
        DemoConsole.Line("A '*' matches one segment in the middle, or one-or-more when it is last.");
        DemoConsole.Blank();

        // (granted pattern, required permission, what we expect) pulled straight from the README table.
        var cases = new (string Pattern, string Required)[]
        {
            ("orders:read", "orders:read"),
            ("orders:read", "orders:write"),
            ("orders:read", "orders:read:detail"),
            ("orders:*", "orders:read"),
            ("orders:*", "orders:read:detail"),
            ("orders:*", "orders"),
            ("orders:*", "billing:read"),
            ("orders:*:read", "orders:eu:read"),
            ("orders:*:read", "orders:eu:write"),
            ("*", "anything:at:all"),
        };

        foreach (var (pattern, required) in cases)
        {
            var granted = PermissionMatcher.IsGranted(pattern, required);
            DemoConsole.Match($"'{pattern}' covers '{required}'", granted);
        }

        DemoConsole.Blank();
        DemoConsole.Line("IsGrantedByAny against a set of held patterns:");
        string[] held = ["billing:read", "orders:*"];
        DemoConsole.Match(
            $"[{string.Join(", ", held)}] covers 'orders:write'",
            PermissionMatcher.IsGrantedByAny(held, "orders:write"));
        DemoConsole.Match(
            $"[{string.Join(", ", held)}] covers 'shipping:read'",
            PermissionMatcher.IsGrantedByAny(held, "shipping:read"));
    }
}

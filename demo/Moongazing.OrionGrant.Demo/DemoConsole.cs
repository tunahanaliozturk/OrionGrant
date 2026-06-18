namespace Moongazing.OrionGrant.Demo;

/// <summary>
/// Tiny console formatting helpers so each feature demo reads cleanly and the output stays uniform.
/// </summary>
internal static class DemoConsole
{
    public static void Section(string title)
    {
        Console.WriteLine();
        Console.WriteLine(new string('=', 72));
        Console.WriteLine(title);
        Console.WriteLine(new string('=', 72));
    }

    public static void Line(string text) => Console.WriteLine(text);

    public static void Blank() => Console.WriteLine();

    /// <summary>Render an authorization decision as a uniform GRANT/DENY line.</summary>
    public static void Decision(string label, AuthorizationResult result)
    {
        if (result.IsGranted)
        {
            Console.WriteLine($"  [GRANT] {label}");
        }
        else
        {
            Console.WriteLine($"  [DENY ] {label} -> {result.FailureReason}");
        }
    }

    public static void Match(string label, bool granted) =>
        Console.WriteLine($"  [{(granted ? "yes" : "no ")}] {label}");
}

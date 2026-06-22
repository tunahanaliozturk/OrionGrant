namespace Moongazing.OrionGrant.Permissions;

/// <summary>
/// Thrown when role-to-role inclusions form a cycle (for example <c>a</c> includes <c>b</c> and
/// <c>b</c> includes <c>a</c>, or a role includes itself). Raised once at registration time while
/// the immutable <see cref="RoleRegistry"/> is built, so a misconfiguration fails fast at startup
/// rather than looping or silently dropping permissions during a request.
/// </summary>
public sealed class RoleInclusionCycleException : InvalidOperationException
{
    /// <summary>Create the exception for a detected cycle.</summary>
    /// <param name="cycle">
    /// The roles forming the cycle, in inclusion order, with the repeated role closing the loop (for
    /// example <c>["a", "b", "a"]</c>).
    /// </param>
    public RoleInclusionCycleException(IReadOnlyList<string> cycle)
        : base(BuildMessage(cycle))
    {
        ArgumentNullException.ThrowIfNull(cycle);
        Cycle = cycle;
    }

    /// <summary>
    /// The roles forming the cycle, in inclusion order, with the repeated role closing the loop.
    /// </summary>
    public IReadOnlyList<string> Cycle { get; }

    private static string BuildMessage(IReadOnlyList<string> cycle)
    {
        ArgumentNullException.ThrowIfNull(cycle);
        return $"Role inclusion cycle detected: {string.Join(" -> ", cycle)}.";
    }
}

namespace Moongazing.OrionGrant.Policies;

/// <summary>
/// An immutable map from policy name to <see cref="AccessPolicy"/>, built once at startup.
/// </summary>
public sealed class PolicyRegistry
{
    private readonly IReadOnlyDictionary<string, AccessPolicy> policies;

    /// <summary>Create a registry from policy definitions.</summary>
    /// <param name="policies">The name-to-policy map.</param>
    public PolicyRegistry(IReadOnlyDictionary<string, AccessPolicy> policies)
    {
        ArgumentNullException.ThrowIfNull(policies);
        this.policies = policies;
    }

    /// <summary>An empty registry (no policies defined).</summary>
    public static PolicyRegistry Empty { get; } =
        new(new Dictionary<string, AccessPolicy>(StringComparer.Ordinal));

    /// <summary>Find a policy by name, or null if none is defined.</summary>
    /// <param name="name">The policy name.</param>
    public AccessPolicy? Find(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        return policies.GetValueOrDefault(name);
    }
}

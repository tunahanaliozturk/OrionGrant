namespace Moongazing.OrionGrant.Policies;

/// <summary>
/// The attribute inputs an attribute-based (ABAC) condition evaluates against: the principal under
/// decision, the optional resource being accessed, and a free-form bag of environment attributes
/// (time of day, request IP, tenant, risk score, and so on). A condition is a pure predicate over
/// this context, so the same policy can allow or deny depending on attribute values rather than on
/// permission membership alone.
/// </summary>
/// <remarks>
/// This composes with the existing model rather than replacing it: a policy's permission requirement
/// is evaluated first (unchanged from 0.3.0), and the condition is an additional AND gate applied
/// only when a condition is configured. The environment bag is an ordinal-keyed string map; when no
/// environment attributes are supplied an empty map is used.
/// </remarks>
public sealed class AuthorizationAttributes
{
    private static readonly IReadOnlyDictionary<string, string?> NoEnvironment =
        new Dictionary<string, string?>(StringComparer.Ordinal);

    /// <summary>Create an attribute context.</summary>
    /// <param name="principal">The principal under decision.</param>
    /// <param name="resource">The resource being accessed, when the decision is resource-scoped.</param>
    /// <param name="environment">
    /// Environment attributes keyed by name (ordinal). Null is treated as an empty map.
    /// </param>
    public AuthorizationAttributes(
        GrantPrincipal principal,
        ResourceContext? resource = null,
        IReadOnlyDictionary<string, string?>? environment = null)
    {
        ArgumentNullException.ThrowIfNull(principal);
        Principal = principal;
        Resource = resource;
        Environment = environment ?? NoEnvironment;
    }

    /// <summary>The principal under decision.</summary>
    public GrantPrincipal Principal { get; }

    /// <summary>The resource being accessed, or null when the decision is not resource-scoped.</summary>
    public ResourceContext? Resource { get; }

    /// <summary>Environment attributes keyed by name. Empty when none were supplied.</summary>
    public IReadOnlyDictionary<string, string?> Environment { get; }

    /// <summary>An attributes context carrying no environment values for the given principal.</summary>
    /// <param name="principal">The principal under decision.</param>
    /// <param name="resource">The resource being accessed, when resource-scoped.</param>
    public static AuthorizationAttributes For(GrantPrincipal principal, ResourceContext? resource = null) =>
        new(principal, resource);

    /// <summary>
    /// Read an environment attribute by name, or null when it is absent. Convenience over indexing
    /// <see cref="Environment"/> directly.
    /// </summary>
    /// <param name="key">The attribute name (ordinal).</param>
    public string? Env(string key)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        return Environment.TryGetValue(key, out var value) ? value : null;
    }
}

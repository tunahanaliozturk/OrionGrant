namespace Moongazing.OrionGrant;

/// <summary>
/// One entry in a batch authorization: the requirement that was checked paired with its
/// <see cref="AuthorizationResult"/>. The <see cref="Requirement"/> echoes the permission or policy
/// name supplied so a caller can correlate results positionally or by name.
/// </summary>
public sealed class BatchAuthorizationResult
{
    /// <summary>Create a batch entry.</summary>
    /// <param name="requirement">The permission or policy name that was checked.</param>
    /// <param name="result">The decision for that requirement.</param>
    public BatchAuthorizationResult(string requirement, AuthorizationResult result)
    {
        ArgumentException.ThrowIfNullOrEmpty(requirement);
        ArgumentNullException.ThrowIfNull(result);
        Requirement = requirement;
        Result = result;
    }

    /// <summary>The permission or policy name this entry was checked against.</summary>
    public string Requirement { get; }

    /// <summary>The decision for <see cref="Requirement"/>.</summary>
    public AuthorizationResult Result { get; }

    /// <summary>Convenience: whether this requirement was granted.</summary>
    public bool IsGranted => Result.IsGranted;
}

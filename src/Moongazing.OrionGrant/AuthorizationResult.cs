namespace Moongazing.OrionGrant;

/// <summary>
/// The outcome of an authorization check: granted, or denied with a human-readable reason useful
/// for logging and for a 403 response body. A denial also carries a structured
/// <see cref="Denial"/> cause so callers can branch on why the check failed without parsing the
/// reason string.
/// </summary>
public sealed class AuthorizationResult
{
    private AuthorizationResult(bool isGranted, string? failureReason, DenialReason? denial)
    {
        IsGranted = isGranted;
        FailureReason = failureReason;
        Denial = denial;
    }

    /// <summary>True when access is granted.</summary>
    public bool IsGranted { get; }

    /// <summary>The reason access was denied, or null when granted.</summary>
    public string? FailureReason { get; }

    /// <summary>
    /// The structured cause of the denial, or null when granted. Carries the denial
    /// <see cref="DenialKind"/> and the relevant identifiers (which permission, which policy, which
    /// mode) so a caller can branch on the cause instead of parsing <see cref="FailureReason"/>.
    /// </summary>
    /// <remarks>
    /// Additive to the original string-only denial: <see cref="FailureReason"/> is unchanged and
    /// still populated for every denial. A result produced by the back-compatible
    /// <see cref="Denied(string)"/> overload has a null <see cref="Denial"/>; the authorizer always
    /// supplies one through <see cref="Denied(string, DenialReason)"/>.
    /// </remarks>
    public DenialReason? Denial { get; }

    /// <summary>The shared granted result.</summary>
    public static AuthorizationResult Granted { get; } =
        new(isGranted: true, failureReason: null, denial: null);

    /// <summary>Create a denied result with a reason and no structured cause.</summary>
    /// <param name="reason">Why access was denied.</param>
    /// <remarks>
    /// Preserved for back-compatibility and ad-hoc denials. Prefer
    /// <see cref="Denied(string, DenialReason)"/> so callers can branch on the structured cause.
    /// </remarks>
    public static AuthorizationResult Denied(string reason)
    {
        ArgumentException.ThrowIfNullOrEmpty(reason);
        return new AuthorizationResult(isGranted: false, reason, denial: null);
    }

    /// <summary>Create a denied result with a reason and its structured cause.</summary>
    /// <param name="reason">Why access was denied, for logging and a 403 body.</param>
    /// <param name="denial">The structured denial cause callers can branch on.</param>
    public static AuthorizationResult Denied(string reason, DenialReason denial)
    {
        ArgumentException.ThrowIfNullOrEmpty(reason);
        ArgumentNullException.ThrowIfNull(denial);
        return new AuthorizationResult(isGranted: false, reason, denial);
    }
}

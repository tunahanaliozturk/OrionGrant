namespace Moongazing.OrionGrant;

/// <summary>
/// The outcome of an authorization check: granted, or denied with a human-readable reason useful
/// for logging and for a 403 response body.
/// </summary>
public sealed class AuthorizationResult
{
    private AuthorizationResult(bool isGranted, string? failureReason)
    {
        IsGranted = isGranted;
        FailureReason = failureReason;
    }

    /// <summary>True when access is granted.</summary>
    public bool IsGranted { get; }

    /// <summary>The reason access was denied, or null when granted.</summary>
    public string? FailureReason { get; }

    /// <summary>The shared granted result.</summary>
    public static AuthorizationResult Granted { get; } = new(isGranted: true, failureReason: null);

    /// <summary>Create a denied result with a reason.</summary>
    /// <param name="reason">Why access was denied.</param>
    public static AuthorizationResult Denied(string reason)
    {
        ArgumentException.ThrowIfNullOrEmpty(reason);
        return new AuthorizationResult(isGranted: false, reason);
    }
}

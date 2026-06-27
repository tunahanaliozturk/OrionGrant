namespace Moongazing.OrionGrant;

/// <summary>
/// The subject of an authorization decision: who is asking, the roles they hold, and any
/// permissions granted to them directly. The authorizer expands roles into permissions and unions
/// them with the direct grants to get the effective permission set.
/// </summary>
public sealed class GrantPrincipal
{
    /// <summary>A stable identifier for the subject (a user id, an API key id, a service name).</summary>
    public required string Subject { get; init; }

    /// <summary>The roles the subject holds. Unknown roles are ignored during expansion.</summary>
    public IReadOnlyCollection<string> Roles { get; init; } = [];

    /// <summary>Permissions granted to the subject directly, in addition to those from roles.</summary>
    public IReadOnlyCollection<string> Permissions { get; init; } = [];

    /// <summary>
    /// Permission patterns explicitly denied to the subject. A deny overrides an allow: if a deny
    /// pattern covers a required permission, the check fails even when a role or direct grant would
    /// otherwise allow it (deny-overrides precedence). Denies use the same wildcard matching as
    /// grants, so <c>orders:*</c> denies every <c>orders:</c> permission. Empty by default, in which
    /// case the principal behaves exactly as in 0.3.0.
    /// </summary>
    public IReadOnlyCollection<string> Denies { get; init; } = [];
}

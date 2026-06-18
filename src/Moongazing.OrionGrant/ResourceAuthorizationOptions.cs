namespace Moongazing.OrionGrant;

/// <summary>
/// Tunes a resource-aware authorization decision: how the principal's identity is compared to the
/// resource owner, and which permissions let a principal bypass the ownership check entirely
/// (the "owner OR elevated" pattern, where an admin or a holder of an "any" grant may act on
/// resources it does not own).
/// </summary>
/// <remarks>
/// The defaults model the most common case: an ordinal owner comparison and no extra elevated
/// permissions beyond whatever the base permission's wildcards already grant. Pass elevated
/// permissions such as <c>accounts:read:any</c> to let privileged principals read every account
/// while ordinary principals are confined to their own.
/// </remarks>
public sealed class ResourceAuthorizationOptions
{
    /// <summary>The shared default options: ordinal owner comparison, no extra elevated permissions.</summary>
    public static ResourceAuthorizationOptions Default { get; } = new();

    /// <summary>
    /// How the principal subject and the resource owner id are compared. Defaults to
    /// <see cref="StringComparison.Ordinal"/>, matching the rest of OrionGrant's permission and role
    /// comparisons. Use a case-insensitive comparison only when subject identifiers are known to be
    /// case-insensitive.
    /// </summary>
    public StringComparison OwnerComparison { get; init; } = StringComparison.Ordinal;

    /// <summary>
    /// Permissions that bypass the ownership check. A principal whose effective permission set
    /// satisfies any of these (via the same wildcard matching used everywhere else) is authorized
    /// for the resource even when it is not the owner. Empty by default.
    /// </summary>
    /// <remarks>
    /// A root <c>*</c> grant already satisfies any elevated permission listed here, so an admin with
    /// <c>*</c> bypasses ownership whenever at least one elevated permission is configured. To let a
    /// bare <c>*</c> grant bypass ownership with no per-call configuration, keep
    /// <see cref="TreatRootWildcardAsElevated"/> enabled.
    /// </remarks>
    public IReadOnlyCollection<string> ElevatedPermissions
    {
        get => elevatedPermissions;
        init => elevatedPermissions = value ?? [];
    }

    private readonly IReadOnlyCollection<string> elevatedPermissions = [];

    /// <summary>
    /// When true (the default), a principal holding the root <c>*</c> permission bypasses ownership
    /// regardless of <see cref="ElevatedPermissions"/>. This keeps an admin/superuser grant working
    /// for object-level checks without configuring an elevated permission per call site.
    /// </summary>
    public bool TreatRootWildcardAsElevated { get; init; } = true;
}

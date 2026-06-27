namespace Moongazing.OrionGrant;

/// <summary>
/// The category of an authorization denial, carried on <see cref="DenialReason"/> so callers can
/// branch on the cause of a denied <see cref="AuthorizationResult"/> instead of parsing the
/// human-readable <see cref="AuthorizationResult.FailureReason"/> string.
/// </summary>
public enum DenialKind
{
    /// <summary>
    /// A required permission was not held by the principal's effective set. Applies to a single
    /// permission check and to the base permission gate of a resource-aware check.
    /// </summary>
    MissingPermission,

    /// <summary>
    /// A named policy was evaluated but no policy is registered under that name.
    /// </summary>
    PolicyNotFound,

    /// <summary>
    /// A named policy was found but its requirement was not satisfied: a
    /// <see cref="Policies.PolicyMode.RequireAll"/> policy was missing at least one listed
    /// permission, or a <see cref="Policies.PolicyMode.RequireAny"/> policy was satisfied by none.
    /// </summary>
    PolicyRequirementUnmet,

    /// <summary>
    /// A resource-aware check passed the base permission gate but the principal neither owned the
    /// resource nor held an elevated grant that bypasses ownership.
    /// </summary>
    ResourceOwnership,

    /// <summary>
    /// An allow covered the required permission but an explicit deny on the principal also covered
    /// it, and a deny overrides an allow (deny-overrides precedence). The
    /// <see cref="DenialReason.Permission"/> names the required permission and
    /// <see cref="DenialReason.DenyPattern"/> names the deny that blocked it.
    /// </summary>
    ExplicitDeny,

    /// <summary>
    /// The permission requirement of a policy was satisfied but an attribute-based (ABAC) condition
    /// attached to the policy evaluated to false for the supplied principal, resource, and
    /// environment attributes. The <see cref="DenialReason.PolicyName"/> names the policy whose
    /// condition was not met.
    /// </summary>
    ConditionUnmet,
}

namespace Moongazing.OrionGrant.Policies;

/// <summary>
/// An attribute-based (ABAC) predicate evaluated against an <see cref="AuthorizationAttributes"/>
/// context as an additional gate on a policy. Returns true to allow and false to deny. The predicate
/// must be pure and side-effect free: it runs on the synchronous authorization hot path and may be
/// evaluated more than once.
/// </summary>
/// <param name="attributes">The principal, resource, and environment attributes to evaluate.</param>
/// <returns>True when the condition is satisfied; false to deny.</returns>
public delegate bool GrantCondition(AuthorizationAttributes attributes);

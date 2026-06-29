namespace Moongazing.OrionGrant.AspNetCore;

using Microsoft.AspNetCore.Authorization;

using Moongazing.OrionGrant.Policies;

using GrantResult = Moongazing.OrionGrant.AuthorizationResult;

/// <summary>
/// The <see cref="AuthorizationHandler{TRequirement}"/> that evaluates an
/// <see cref="OrionGrantRequirement"/> for the current <see cref="System.Security.Claims.ClaimsPrincipal"/>:
/// it resolves the principal's OrionGrant grants through <see cref="IGrantPrincipalResolver"/> and
/// runs the matching OrionGrant check on <see cref="IGrantAuthorizer"/>. On success it succeeds the
/// requirement; on denial it calls <see cref="AuthorizationHandlerContext.Fail(AuthorizationFailureReason)"/>
/// with an <see cref="OrionGrantAuthorizationFailureReason"/> carrying the structured
/// <see cref="DenialReason"/>.
/// </summary>
/// <remarks>
/// <para>
/// When the authorization call supplies a resource (resource-based authorization), a permission
/// requirement is evaluated with OrionGrant's object-level / ownership-aware overload against the
/// resource's <see cref="ResourceContext"/>, and a policy requirement surfaces that
/// <see cref="ResourceContext"/> to the policy's attribute-based (ABAC) condition. An unresolved
/// principal (anonymous or no subject claim) fails the requirement with a denied result rather than
/// throwing.
/// </para>
/// <para>
/// The handler is registered scoped (see
/// <see cref="OrionGrantAspNetCoreServiceCollectionExtensions.AddOrionGrantAuthorization"/>) so it
/// may depend on a scoped <see cref="IGrantPrincipalResolver"/> (for example one consulting a scoped
/// store) without becoming a captive dependency. Resource-based authorization fails closed: a
/// non-null resource of a type the handler does not understand denies rather than degrading to a
/// permission-only check.
/// </para>
/// </remarks>
public sealed class OrionGrantAuthorizationHandler : AuthorizationHandler<OrionGrantRequirement>
{
    private readonly IGrantAuthorizer authorizer;
    private readonly IGrantPrincipalResolver principalResolver;

    /// <summary>Create the handler.</summary>
    /// <param name="authorizer">The OrionGrant authorizer that decides the check.</param>
    /// <param name="principalResolver">Resolves the OrionGrant principal for the current user.</param>
    public OrionGrantAuthorizationHandler(
        IGrantAuthorizer authorizer,
        IGrantPrincipalResolver principalResolver)
    {
        ArgumentNullException.ThrowIfNull(authorizer);
        ArgumentNullException.ThrowIfNull(principalResolver);
        this.authorizer = authorizer;
        this.principalResolver = principalResolver;
    }

    /// <inheritdoc />
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        OrionGrantRequirement requirement)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requirement);

        var principal = await principalResolver
            .ResolveAsync(context.User, CancellationToken.None)
            .ConfigureAwait(false);

        if (principal is null)
        {
            Fail(context, requirement, GrantResult.Denied(
                "No OrionGrant principal could be resolved for the current user.",
                UnresolvedPrincipalDenial(requirement)));
            return;
        }

        var result = Evaluate(principal, requirement, context.Resource);

        if (result.IsGranted)
        {
            context.Succeed(requirement);
        }
        else
        {
            Fail(context, requirement, result);
        }
    }

    private GrantResult Evaluate(
        GrantPrincipal principal,
        OrionGrantRequirement requirement,
        object? resource)
    {
        if (requirement.Kind == OrionGrantRequirementKind.Policy)
        {
            return EvaluatePolicy(principal, requirement.Value, resource);
        }

        return EvaluatePermission(principal, requirement.Value, resource);
    }

    private GrantResult EvaluatePolicy(GrantPrincipal principal, string policyName, object? resource)
    {
        // A policy requirement surfaces the resource's attributes to the policy's ABAC condition, so a
        // condition that reads AuthorizationAttributes.Resource sees the object being accessed. A bare
        // permission policy ignores them. Resolving the resource fails closed (see ResolveResource).
        if (!TryResolveResource(resource, out var context, out _))
        {
            return ResourceTypeNotSupported(policyName);
        }

        return context is null
            ? authorizer.AuthorizePolicy(principal, policyName)
            : authorizer.AuthorizePolicy(
                principal,
                policyName,
                new AuthorizationAttributes(principal, context));
    }

    private GrantResult EvaluatePermission(GrantPrincipal principal, string permission, object? resource)
    {
        if (!TryResolveResource(resource, out var context, out var options))
        {
            return ResourceTypeNotSupported(permission);
        }

        return context is null
            ? authorizer.Authorize(principal, permission)
            : authorizer.Authorize(principal, permission, context, options);
    }

    /// <summary>
    /// Map the framework resource to an OrionGrant <see cref="ResourceContext"/> (and any
    /// <see cref="ResourceAuthorizationOptions"/>). A null resource maps to a null context (a plain,
    /// non-resource check). A resource of an understood type yields its context. Any other non-null
    /// resource type is unsupported and returns false so the caller fails closed rather than silently
    /// evaluating a weaker, non-resource check against a resource the integration does not understand.
    /// </summary>
    private static bool TryResolveResource(
        object? resource,
        out ResourceContext? context,
        out ResourceAuthorizationOptions? options)
    {
        switch (resource)
        {
            case null:
                context = null;
                options = null;
                return true;
            case OrionGrantResource og:
                context = og.Context;
                options = og.Options;
                return true;
            case ResourceContext ctx:
                context = ctx;
                options = null;
                return true;
            default:
                context = null;
                options = null;
                return false;
        }
    }

    private static GrantResult ResourceTypeNotSupported(string value) =>
        GrantResult.Denied(
            "Resource-based authorization was supplied a resource of a type the OrionGrant " +
            "integration does not understand; the request is denied (fail closed). Pass an " +
            $"{nameof(OrionGrantResource)} or {nameof(ResourceContext)} as the resource. Requirement: '{value}'.",
            DenialReason.MissingPermission(value));

    private static DenialReason UnresolvedPrincipalDenial(OrionGrantRequirement requirement) =>
        requirement.Kind == OrionGrantRequirementKind.Policy
            ? DenialReason.PolicyRequireAnyUnmet(requirement.Value)
            : DenialReason.MissingPermission(requirement.Value);

    private void Fail(
        AuthorizationHandlerContext context,
        OrionGrantRequirement requirement,
        GrantResult result)
    {
        context.Fail(new OrionGrantAuthorizationFailureReason(this, requirement, result));
    }
}

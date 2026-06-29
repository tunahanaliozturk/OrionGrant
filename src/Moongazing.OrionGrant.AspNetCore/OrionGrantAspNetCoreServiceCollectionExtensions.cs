namespace Moongazing.OrionGrant.AspNetCore;

using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

/// <summary>
/// Registration helpers that bridge OrionGrant into the ASP.NET Core authorization pipeline.
/// </summary>
public static class OrionGrantAspNetCoreServiceCollectionExtensions
{
    /// <summary>
    /// Register the complete OrionGrant ASP.NET Core integration in one call: the framework
    /// authorization services (via <c>AddAuthorization</c>), the core OrionGrant services (via
    /// <see cref="OrionGrantServiceCollectionExtensions.AddOrionGrant"/>), the
    /// <see cref="OrionGrantAuthorizationHandler"/>, the default claims-based
    /// <see cref="IGrantPrincipalResolver"/>, the <see cref="OrionGrantPolicyProvider"/> so
    /// <c>perm:</c> / <c>policy:</c> policy names resolve to OrionGrant checks, and validated
    /// <see cref="OrionGrantClaimsOptions"/> / <see cref="OrionGrantPolicyNameOptions"/>. After this
    /// call no further authorization wiring is required for the integration to work.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Optional OrionGrant role and policy configuration, as on the core method.</param>
    /// <returns>An <see cref="IOrionGrantAspNetCoreBuilder"/> for further configuration.</returns>
    public static IOrionGrantAspNetCoreBuilder AddOrionGrantAuthorization(
        this IServiceCollection services,
        Action<OrionGrantBuilder>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        // One-call registration: pull in the framework's authorization services ourselves rather than
        // assuming the caller already did. AddAuthorization is idempotent (it TryAdds the policy
        // service, evaluator, options, and default provider), so calling it here is safe even when the
        // application also calls it. Without this, IAuthorizationService and AuthorizationOptions would
        // be missing unless the caller wired them separately.
        services.AddAuthorization();

        services.AddOrionGrant(configure);

        // Validate the option types at startup so a misconfigured claim type or null policy-name prefix
        // fails fast with a clear message instead of silently mis-resolving principals or policy names.
        services
            .AddOptions<OrionGrantClaimsOptions>()
            .Validate(
                OrionGrantClaimsOptions.IsValid,
                OrionGrantClaimsOptions.ValidationError)
            .ValidateOnStart();
        services
            .AddOptions<OrionGrantPolicyNameOptions>()
            .Validate(
                OrionGrantPolicyNameOptions.IsValid,
                OrionGrantPolicyNameOptions.ValidationError)
            .ValidateOnStart();

        services.TryAddSingleton<IGrantPrincipalResolver, ClaimsGrantPrincipalResolver>();

        // Scoped, not singleton: the handler depends on IGrantPrincipalResolver, which an application
        // may replace with a scoped implementation (one consulting a scoped store or DbContext).
        // A singleton handler capturing a scoped resolver is a captive dependency that throws under
        // ValidateScopes (the default in Development). Scoped matches the broadest dependency lifetime
        // and is the lifetime the framework resolves handlers at per request.
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IAuthorizationHandler, OrionGrantAuthorizationHandler>());

        // Replace, not TryAdd: AddAuthorization (above) already registered
        // DefaultAuthorizationPolicyProvider, so a TryAdd would be a no-op and the perm: / policy:
        // names would never resolve. The OrionGrant provider wraps the default and defers to it for
        // every name it does not own, so registered policies keep working.
        services.Replace(
            ServiceDescriptor.Singleton<IAuthorizationPolicyProvider, OrionGrantPolicyProvider>());

        return new OrionGrantAspNetCoreBuilder(services);
    }

    private sealed class OrionGrantAspNetCoreBuilder(IServiceCollection services) : IOrionGrantAspNetCoreBuilder
    {
        public IServiceCollection Services { get; } = services;
    }
}

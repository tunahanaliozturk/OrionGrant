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
    /// Register the OrionGrant ASP.NET Core integration: the core OrionGrant services (via
    /// <see cref="OrionGrantServiceCollectionExtensions.AddOrionGrant"/>), the
    /// <see cref="OrionGrantAuthorizationHandler"/>, the default claims-based
    /// <see cref="IGrantPrincipalResolver"/>, and the <see cref="OrionGrantPolicyProvider"/> so
    /// <c>perm:</c> / <c>policy:</c> policy names resolve to OrionGrant checks. Call
    /// <c>AddAuthorization</c> (or rely on the framework doing so) for the rest of the authorization
    /// services.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Optional OrionGrant role and policy configuration, as on the core method.</param>
    /// <returns>An <see cref="IOrionGrantAspNetCoreBuilder"/> for further configuration.</returns>
    public static IOrionGrantAspNetCoreBuilder AddOrionGrantAuthorization(
        this IServiceCollection services,
        Action<OrionGrantBuilder>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOrionGrant(configure);

        services.AddOptions<OrionGrantClaimsOptions>();
        services.AddOptions<OrionGrantPolicyNameOptions>();

        services.TryAddSingleton<IGrantPrincipalResolver, ClaimsGrantPrincipalResolver>();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IAuthorizationHandler, OrionGrantAuthorizationHandler>());

        // Replace, not TryAdd: the framework's AddAuthorization already registers
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

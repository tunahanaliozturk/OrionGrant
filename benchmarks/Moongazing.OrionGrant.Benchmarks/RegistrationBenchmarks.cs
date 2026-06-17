namespace Moongazing.OrionGrant.Benchmarks;

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;

using Microsoft.Extensions.DependencyInjection;

using Moongazing.OrionGrant;
using Moongazing.OrionGrant.Policies;

/// <summary>
/// Measures the one-time startup path: declaring roles and policies through
/// <see cref="OrionGrantServiceCollectionExtensions.AddOrionGrant"/>, which folds them into the
/// immutable registries and registers the authorizer. Not on the request hot path, but it is what
/// runs at application boot, so its allocation profile is worth tracking. Resolving the authorizer
/// afterwards forces the registry builds to actually execute.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net80)]
[SimpleJob(RuntimeMoniker.Net90)]
public class RegistrationBenchmarks
{
    [Benchmark]
    public IGrantAuthorizer RegisterAndResolve()
    {
        var services = new ServiceCollection();
        services.AddOrionGrant(grant => grant
            .AddRole("orders.manager", "orders:*")
            .AddRole("auditor", "orders:read", "billing:read", "reports:*")
            .AddRole("admin", "*")
            .AddPolicy("orders.write", PolicyMode.RequireAll, "orders:write")
            .AddPolicy("orders.touch", PolicyMode.RequireAny, "orders:read", "orders:write")
            .AddPolicy("billing.manage", PolicyMode.RequireAll, "billing:read", "billing:write"));

        using var provider = services.BuildServiceProvider();
        return provider.GetRequiredService<IGrantAuthorizer>();
    }
}

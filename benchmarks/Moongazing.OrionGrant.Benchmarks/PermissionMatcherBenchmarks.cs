namespace Moongazing.OrionGrant.Benchmarks;

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;

using Moongazing.OrionGrant.Permissions;

/// <summary>
/// Measures the pure wildcard matcher: the split-and-compare core that every authorization
/// decision ultimately runs through. Covers an exact match, a trailing wildcard, a deep
/// wildcard, and a non-match (which scans the whole granted set before failing).
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net80)]
[SimpleJob(RuntimeMoniker.Net90)]
public class PermissionMatcherBenchmarks
{
    private static readonly string[] GrantedSet =
    [
        "billing:read",
        "billing:write",
        "orders:read",
        "orders:write",
        "orders:eu:*",
        "reports:*",
        "users:read",
    ];

    [Benchmark]
    public bool ExactMatch() => PermissionMatcher.IsGranted("orders:read", "orders:read");

    [Benchmark]
    public bool TrailingWildcard() => PermissionMatcher.IsGranted("orders:*", "orders:read:detail");

    [Benchmark]
    public bool MiddleWildcard() => PermissionMatcher.IsGranted("orders:*:read", "orders:eu:read");

    [Benchmark]
    public bool RootWildcard() => PermissionMatcher.IsGranted("*", "orders:read:detail");

    [Benchmark]
    public bool NonMatch() => PermissionMatcher.IsGranted("orders:read", "orders:write");

    [Benchmark]
    public bool IsGrantedByAny_Hit() => PermissionMatcher.IsGrantedByAny(GrantedSet, "orders:write");

    [Benchmark]
    public bool IsGrantedByAny_Miss() => PermissionMatcher.IsGrantedByAny(GrantedSet, "secrets:read");
}

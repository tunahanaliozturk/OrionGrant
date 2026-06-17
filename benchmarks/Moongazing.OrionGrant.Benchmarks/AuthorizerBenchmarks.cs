namespace Moongazing.OrionGrant.Benchmarks;

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;

using Moongazing.OrionGrant;
using Moongazing.OrionGrant.Diagnostics;
using Moongazing.OrionGrant.Permissions;
using Moongazing.OrionGrant.Policies;

/// <summary>
/// Measures the full authorization path: role expansion into an effective permission set
/// (a HashSet union, the main per-call allocation) followed by wildcard matching. Covers a
/// direct permission check, an allow and a deny, and both policy modes.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net80)]
[SimpleJob(RuntimeMoniker.Net90)]
public class AuthorizerBenchmarks
{
    private GrantAuthorizer authorizer = null!;
    private GrantPrincipal principal = null!;
    private GrantDiagnostics diagnostics = null!;

    [GlobalSetup]
    public void Setup()
    {
        var roles = new RoleRegistry(new Dictionary<string, IReadOnlySet<string>>(StringComparer.Ordinal)
        {
            ["orders.manager"] = new HashSet<string>(StringComparer.Ordinal) { "orders:*" },
            ["auditor"] = new HashSet<string>(StringComparer.Ordinal) { "orders:read", "billing:read", "reports:*" },
        });

        var policies = new PolicyRegistry(new Dictionary<string, AccessPolicy>(StringComparer.Ordinal)
        {
            ["orders.write"] = new AccessPolicy("orders.write", PolicyMode.RequireAll, ["orders:write"]),
            ["orders.touch"] = new AccessPolicy("orders.touch", PolicyMode.RequireAny, ["orders:read", "orders:write"]),
            ["broad"] = new AccessPolicy("broad", PolicyMode.RequireAll, ["orders:read", "billing:read", "reports:daily"]),
        });

        diagnostics = new GrantDiagnostics();
        authorizer = new GrantAuthorizer(roles, policies, diagnostics);

        principal = new GrantPrincipal
        {
            Subject = "api-key-42",
            Roles = ["auditor"],
            Permissions = ["users:read", "billing:write"],
        };
    }

    [GlobalCleanup]
    public void Cleanup() => diagnostics.Dispose();

    [Benchmark]
    public IReadOnlySet<string> EffectivePermissions() => authorizer.EffectivePermissions(principal);

    [Benchmark]
    public AuthorizationResult Authorize_Granted() => authorizer.Authorize(principal, "orders:read");

    [Benchmark]
    public AuthorizationResult Authorize_Denied() => authorizer.Authorize(principal, "secrets:read");

    [Benchmark]
    public AuthorizationResult AuthorizePolicy_RequireAny() => authorizer.AuthorizePolicy(principal, "orders.touch");

    [Benchmark]
    public AuthorizationResult AuthorizePolicy_RequireAll() => authorizer.AuthorizePolicy(principal, "broad");
}

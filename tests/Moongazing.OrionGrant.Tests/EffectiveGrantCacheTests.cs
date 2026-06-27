namespace Moongazing.OrionGrant.Tests;

using System;
using System.Linq;

using Moongazing.OrionGrant;
using Moongazing.OrionGrant.Diagnostics;
using Moongazing.OrionGrant.Permissions;

using Xunit;

/// <summary>
/// Coverage of the per-principal effective-set cache. The cached authorizer must return the same
/// decision as the uncached one for every input, must not serve a stale decision when a principal's
/// role / permission / deny membership changes (the key is derived from that membership), and the
/// bounded cache must cap its size by evicting least-recently-used entries. Determinism is required:
/// no test depends on wall-clock time or iteration order.
/// </summary>
public sealed class EffectiveGrantCacheTests
{
    private static (GrantAuthorizer Cached, GrantAuthorizer Uncached) BuildPair(
        GrantDiagnostics diagnostics,
        BoundedEffectiveGrantCache cache,
        Action<OrionGrantBuilder>? configure = null)
    {
        var builder = new OrionGrantBuilder();
        configure?.Invoke(builder);
        var roles = builder.BuildRoles();
        var policies = builder.BuildPolicies();
        return (
            new GrantAuthorizer(roles, policies, diagnostics, cache),
            new GrantAuthorizer(roles, policies, diagnostics));
    }

    [Fact]
    public void Cached_decision_equals_uncached_for_allow_deny_and_role_paths()
    {
        using var diag = new GrantDiagnostics();
        var cache = new BoundedEffectiveGrantCache();
        var (cached, uncached) = BuildPair(diag, cache, b => b
            .AddRole("reader", "orders:read", "orders:write")
            .AddRole("admin", "*"));

        var principals = new[]
        {
            new GrantPrincipal { Subject = "u1", Roles = ["reader"] },
            new GrantPrincipal { Subject = "u2", Roles = ["reader"], Denies = ["orders:write"] },
            new GrantPrincipal { Subject = "u3", Roles = ["admin"] },
            new GrantPrincipal { Subject = "u4", Permissions = ["billing:read"] },
            new GrantPrincipal { Subject = "u5" },
        };
        var checks = new[] { "orders:read", "orders:write", "billing:read", "accounts:delete" };

        foreach (var principal in principals)
        {
            foreach (var permission in checks)
            {
                Assert.Equal(
                    uncached.Authorize(principal, permission).IsGranted,
                    cached.Authorize(principal, permission).IsGranted);
            }
        }
    }

    [Fact]
    public void Repeated_checks_for_the_same_principal_reuse_one_entry()
    {
        using var diag = new GrantDiagnostics();
        var cache = new BoundedEffectiveGrantCache();
        var (cached, _) = BuildPair(diag, cache, b => b.AddRole("reader", "orders:read"));
        var principal = new GrantPrincipal { Subject = "u1", Roles = ["reader"] };

        for (var i = 0; i < 10; i++)
        {
            Assert.True(cached.Authorize(principal, "orders:read").IsGranted);
        }

        // All ten checks were the same membership, so exactly one entry was stored.
        Assert.Equal(1, cache.Count);
    }

    [Fact]
    public void A_changed_role_set_does_not_serve_a_stale_decision()
    {
        using var diag = new GrantDiagnostics();
        var cache = new BoundedEffectiveGrantCache();
        var (cached, _) = BuildPair(diag, cache, b => b
            .AddRole("reader", "orders:read")
            .AddRole("writer", "orders:write"));

        var asReader = new GrantPrincipal { Subject = "u1", Roles = ["reader"] };
        Assert.True(cached.Authorize(asReader, "orders:read").IsGranted);
        Assert.False(cached.Authorize(asReader, "orders:write").IsGranted);

        // The same subject now holds a different role set. A subject-keyed cache would wrongly reuse
        // the reader entry; the membership-keyed cache computes a new key and gives the fresh answer.
        var asWriter = new GrantPrincipal { Subject = "u1", Roles = ["writer"] };
        Assert.False(cached.Authorize(asWriter, "orders:read").IsGranted);
        Assert.True(cached.Authorize(asWriter, "orders:write").IsGranted);

        Assert.Equal(2, cache.Count);
    }

    [Fact]
    public void Adding_a_deny_to_the_same_subject_does_not_serve_a_stale_allow()
    {
        using var diag = new GrantDiagnostics();
        var cache = new BoundedEffectiveGrantCache();
        var (cached, _) = BuildPair(diag, cache, b => b.AddRole("reader", "orders:read"));

        var before = new GrantPrincipal { Subject = "u1", Roles = ["reader"] };
        Assert.True(cached.Authorize(before, "orders:read").IsGranted);

        // Same subject and roles, but now an explicit deny. Different membership, different key.
        var after = new GrantPrincipal { Subject = "u1", Roles = ["reader"], Denies = ["orders:read"] };
        Assert.False(cached.Authorize(after, "orders:read").IsGranted);
    }

    [Fact]
    public void Cache_key_is_independent_of_collection_order()
    {
        using var diag = new GrantDiagnostics();
        var cache = new BoundedEffectiveGrantCache();
        var (cached, _) = BuildPair(diag, cache, b => b
            .AddRole("a", "p:a")
            .AddRole("b", "p:b"));

        var oneOrder = new GrantPrincipal { Subject = "u1", Roles = ["a", "b"] };
        var otherOrder = new GrantPrincipal { Subject = "u2", Roles = ["b", "a"] };

        Assert.True(cached.Authorize(oneOrder, "p:a").IsGranted);
        Assert.True(cached.Authorize(otherOrder, "p:a").IsGranted);

        // Same membership in a different order must hit the same entry.
        Assert.Equal(1, cache.Count);
    }

    [Fact]
    public void Bounded_cache_evicts_least_recently_used_over_capacity()
    {
        using var diag = new GrantDiagnostics();
        var cache = new BoundedEffectiveGrantCache(capacity: 2);
        var (cached, _) = BuildPair(diag, cache);

        // Three distinct memberships into a capacity-2 cache: the count never exceeds the bound.
        cached.Authorize(new GrantPrincipal { Subject = "u1", Permissions = ["p:1"] }, "p:1");
        cached.Authorize(new GrantPrincipal { Subject = "u2", Permissions = ["p:2"] }, "p:2");
        cached.Authorize(new GrantPrincipal { Subject = "u3", Permissions = ["p:3"] }, "p:3");

        Assert.Equal(2, cache.Count);
    }

    [Fact]
    public void Bounded_cache_after_eviction_still_returns_correct_decisions()
    {
        using var diag = new GrantDiagnostics();
        var cache = new BoundedEffectiveGrantCache(capacity: 1);
        var (cached, uncached) = BuildPair(diag, cache);

        var p1 = new GrantPrincipal { Subject = "u1", Permissions = ["orders:read"] };
        var p2 = new GrantPrincipal { Subject = "u2", Permissions = ["billing:read"] };

        // Force eviction by alternating, then verify each still matches the uncached truth.
        for (var i = 0; i < 5; i++)
        {
            Assert.Equal(uncached.Authorize(p1, "orders:read").IsGranted, cached.Authorize(p1, "orders:read").IsGranted);
            Assert.Equal(uncached.Authorize(p1, "billing:read").IsGranted, cached.Authorize(p1, "billing:read").IsGranted);
            Assert.Equal(uncached.Authorize(p2, "orders:read").IsGranted, cached.Authorize(p2, "orders:read").IsGranted);
            Assert.Equal(uncached.Authorize(p2, "billing:read").IsGranted, cached.Authorize(p2, "billing:read").IsGranted);
        }

        Assert.Equal(1, cache.Count);
    }

    [Fact]
    public void EffectivePermissions_is_served_from_the_cache_and_matches_uncached()
    {
        using var diag = new GrantDiagnostics();
        var cache = new BoundedEffectiveGrantCache();
        var (cached, uncached) = BuildPair(diag, cache, b => b
            .AddRole("reader", "orders:read", "billing:read"));
        var principal = new GrantPrincipal { Subject = "u1", Roles = ["reader"], Permissions = ["audit:read"] };

        var fromCache = cached.EffectivePermissions(principal).OrderBy(x => x, StringComparer.Ordinal);
        var direct = uncached.EffectivePermissions(principal).OrderBy(x => x, StringComparer.Ordinal);

        Assert.Equal(direct, fromCache);
        Assert.Equal(1, cache.Count);
    }

    [Fact]
    public void Builder_opt_in_cache_produces_the_same_decisions()
    {
        // Via the builder's UseEffectiveSetCache rather than constructing the cache by hand.
        using var diag = new GrantDiagnostics();
        var builder = new OrionGrantBuilder()
            .AddRole("reader", "orders:read")
            .UseEffectiveSetCache(capacity: 8);
        var cache = builder.BuildEffectiveGrantCache();
        Assert.NotNull(cache);

        var authorizer = new GrantAuthorizer(builder.BuildRoles(), builder.BuildPolicies(), diag, cache);
        var principal = new GrantPrincipal { Subject = "u1", Roles = ["reader"] };

        Assert.True(authorizer.Authorize(principal, "orders:read").IsGranted);
        Assert.False(authorizer.Authorize(principal, "orders:write").IsGranted);
    }

    [Fact]
    public void Default_builder_requests_no_cache()
    {
        var builder = new OrionGrantBuilder().AddRole("reader", "orders:read");
        Assert.Null(builder.BuildEffectiveGrantCache());
    }

    [Fact]
    public void Cache_capacity_must_be_positive()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new BoundedEffectiveGrantCache(capacity: 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new OrionGrantBuilder().UseEffectiveSetCache(-1));
    }
}

namespace Moongazing.OrionGrant.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Linq;

using Moongazing.OrionGrant;
using Moongazing.OrionGrant.Diagnostics;
using Moongazing.OrionGrant.Policies;

using Xunit;

/// <summary>
/// Coverage of batch checks: <see cref="GrantAuthorizer.AuthorizeAll"/> and
/// <see cref="GrantAuthorizer.AuthorizeAllPolicies"/> return one result per requirement in input
/// order, each result matches what the equivalent single call produces (granted flag and structured
/// denial), empty input yields empty output, and arguments are validated. The single-check parity
/// checks are the load-bearing assertions: batch must be an optimization, not a behavior change.
/// </summary>
/// <remarks>
/// Joins the non-parallel <c>MeterListener</c> collection because one test attaches a
/// <see cref="MeterListener"/> to the shared meter; it still filters by its own instrument instance,
/// matching the convention in the diagnostics instance-scoping tests.
/// </remarks>
[Collection("MeterListener")]
public sealed class BatchAuthorizationTests
{
    private static GrantAuthorizer Build(
        GrantDiagnostics diagnostics,
        Action<OrionGrantBuilder>? configure = null)
    {
        var builder = new OrionGrantBuilder();
        configure?.Invoke(builder);
        return new GrantAuthorizer(builder.BuildRoles(), builder.BuildPolicies(), diagnostics);
    }

    [Fact]
    public void AuthorizeAll_returns_one_result_per_permission_in_order()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:read", "billing:read"] };

        var results = authorizer.AuthorizeAll(
            principal, ["orders:read", "orders:write", "billing:read"]);

        Assert.Equal(3, results.Count);
        Assert.Equal(["orders:read", "orders:write", "billing:read"], results.Select(r => r.Requirement));
        Assert.True(results[0].IsGranted);
        Assert.False(results[1].IsGranted);
        Assert.True(results[2].IsGranted);
    }

    [Fact]
    public void AuthorizeAll_each_item_matches_the_single_check_result()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b.AddRole("reader", "orders:*"));
        var principal = new GrantPrincipal { Subject = "u1", Roles = ["reader"], Permissions = ["billing:read"] };
        string[] required = ["orders:read", "orders:eu:write", "billing:read", "billing:write", "*"];

        var batch = authorizer.AuthorizeAll(principal, required);

        for (var i = 0; i < required.Length; i++)
        {
            var single = authorizer.Authorize(principal, required[i]);
            Assert.Equal(single.IsGranted, batch[i].IsGranted);
            Assert.Equal(required[i], batch[i].Requirement);
        }
    }

    [Fact]
    public void AuthorizeAll_denied_item_carries_the_same_structured_denial_as_a_single_check()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1" };

        var batch = authorizer.AuthorizeAll(principal, ["orders:read"]);
        var single = authorizer.Authorize(principal, "orders:read");

        var singleDenial = Assert.IsType<DenialReason>(single.Denial);
        var batchDenial = Assert.IsType<DenialReason>(batch[0].Result.Denial);
        Assert.Equal(singleDenial.Kind, batchDenial.Kind);
        Assert.Equal(singleDenial.Permission, batchDenial.Permission);
        Assert.Equal(DenialKind.MissingPermission, batchDenial.Kind);
    }

    [Fact]
    public void AuthorizeAll_on_empty_input_returns_empty()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1" };

        Assert.Empty(authorizer.AuthorizeAll(principal, []));
    }

    [Fact]
    public void AuthorizeAll_records_one_decision_per_item()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:read"] };

        var outcomes = CollectOutcomes(
            diag,
            () => authorizer.AuthorizeAll(principal, ["orders:read", "orders:write", "billing:read"]));

        // One measurement per requirement, mirroring three separate Authorize calls.
        Assert.Equal(3, outcomes.Count);
        Assert.Equal(1, outcomes.Count(o => o == "granted"));
        Assert.Equal(2, outcomes.Count(o => o == "denied"));
    }

    /// <summary>
    /// Captures the <c>outcome</c> tag of every decision recorded by the given diagnostics instance
    /// while <paramref name="act"/> runs, filtering strictly on that instance's counter instrument so
    /// a concurrently running test on the shared meter name cannot leak measurements in.
    /// </summary>
    private static List<string> CollectOutcomes(GrantDiagnostics diagnostics, Action act)
    {
        var outcomes = new List<string>();

        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (ReferenceEquals(instrument, diagnostics.Decisions))
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, value, tags, state) =>
        {
            foreach (var tag in tags)
            {
                if (tag.Key == "outcome")
                {
                    outcomes.Add((string)tag.Value!);
                }
            }
        });
        listener.Start();

        act();

        return outcomes;
    }

    [Fact]
    public void AuthorizeAll_throws_when_principal_is_null()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);

        Assert.Throws<ArgumentNullException>(() => authorizer.AuthorizeAll(null!, ["orders:read"]));
    }

    [Fact]
    public void AuthorizeAll_throws_when_collection_is_null()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1" };

        Assert.Throws<ArgumentNullException>(() => authorizer.AuthorizeAll(principal, null!));
    }

    [Fact]
    public void AuthorizeAll_throws_when_a_permission_entry_is_null_or_empty()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1" };

        Assert.ThrowsAny<ArgumentException>(
            () => authorizer.AuthorizeAll(principal, ["orders:read", ""]));
        Assert.ThrowsAny<ArgumentException>(
            () => authorizer.AuthorizeAll(principal, ["orders:read", null!]));
    }

    [Fact]
    public void AuthorizeAllPolicies_returns_one_result_per_policy_in_order()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b
            .AddPolicy("orders.read", PolicyMode.RequireAny, "orders:read")
            .AddPolicy("orders.write", PolicyMode.RequireAll, "orders:write"));
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:read"] };

        var results = authorizer.AuthorizeAllPolicies(principal, ["orders.read", "orders.write", "ghost"]);

        Assert.Equal(["orders.read", "orders.write", "ghost"], results.Select(r => r.Requirement));
        Assert.True(results[0].IsGranted);
        Assert.False(results[1].IsGranted);
        Assert.False(results[2].IsGranted);
    }

    [Fact]
    public void AuthorizeAllPolicies_each_item_matches_the_single_check_result()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b
            .AddPolicy("orders.manage", PolicyMode.RequireAll, "orders:read", "orders:write")
            .AddPolicy("orders.touch", PolicyMode.RequireAny, "orders:read", "orders:write"));
        var principal = new GrantPrincipal { Subject = "u1", Permissions = ["orders:read"] };
        string[] names = ["orders.manage", "orders.touch", "missing"];

        var batch = authorizer.AuthorizeAllPolicies(principal, names);

        for (var i = 0; i < names.Length; i++)
        {
            var single = authorizer.AuthorizePolicy(principal, names[i]);
            Assert.Equal(single.IsGranted, batch[i].IsGranted);
            Assert.Equal(single.Denial?.Kind, batch[i].Result.Denial?.Kind);
        }
    }

    [Fact]
    public void AuthorizeAllPolicies_unknown_policy_item_is_policy_not_found()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1" };

        var results = authorizer.AuthorizeAllPolicies(principal, ["ghost"]);

        Assert.False(results[0].IsGranted);
        var denial = Assert.IsType<DenialReason>(results[0].Result.Denial);
        Assert.Equal(DenialKind.PolicyNotFound, denial.Kind);
        Assert.Equal("ghost", denial.PolicyName);
    }

    [Fact]
    public void AuthorizeAllPolicies_on_empty_input_returns_empty()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag);
        var principal = new GrantPrincipal { Subject = "u1" };

        Assert.Empty(authorizer.AuthorizeAllPolicies(principal, []));
    }

    [Fact]
    public void AuthorizeAllPolicies_throws_when_a_policy_name_entry_is_null_or_empty()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b.AddPolicy("p", PolicyMode.RequireAny, "orders:read"));
        var principal = new GrantPrincipal { Subject = "u1" };

        Assert.ThrowsAny<ArgumentException>(
            () => authorizer.AuthorizeAllPolicies(principal, ["p", ""]));
    }

    [Fact]
    public void Batch_entry_exposes_requirement_and_granted_shortcut()
    {
        var entry = new BatchAuthorizationResult("orders:read", AuthorizationResult.Granted);

        Assert.Equal("orders:read", entry.Requirement);
        Assert.True(entry.IsGranted);
        Assert.Same(AuthorizationResult.Granted, entry.Result);
    }

    [Fact]
    public void Batch_entry_validates_its_arguments()
    {
        Assert.ThrowsAny<ArgumentException>(
            () => new BatchAuthorizationResult("", AuthorizationResult.Granted));
        Assert.Throws<ArgumentNullException>(
            () => new BatchAuthorizationResult("orders:read", null!));
    }
}

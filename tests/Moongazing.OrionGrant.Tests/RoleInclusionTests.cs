namespace Moongazing.OrionGrant.Tests;

using System;
using System.Linq;

using Moongazing.OrionGrant;
using Moongazing.OrionGrant.Diagnostics;
using Moongazing.OrionGrant.Permissions;

using Xunit;

/// <summary>
/// Coverage of role-to-role inclusion: transitive permission composition through
/// <see cref="OrionGrantBuilder.IncludeRole"/>, diamond inclusion, included-but-undefined roles,
/// inclusion introspection on <see cref="RoleRegistry"/>, and cycle detection at build time. The
/// transitive set is verified both directly on the registry and through the authorizer's effective
/// set, since that is how a principal's roles are expanded.
/// </summary>
public sealed class RoleInclusionTests
{
    private static GrantAuthorizer Build(
        GrantDiagnostics diagnostics,
        Action<OrionGrantBuilder> configure)
    {
        var builder = new OrionGrantBuilder();
        configure(builder);
        return new GrantAuthorizer(builder.BuildRoles(), builder.BuildPolicies(), diagnostics);
    }

    [Fact]
    public void Including_a_role_folds_in_its_permissions()
    {
        var registry = new OrionGrantBuilder()
            .AddRole("reader", "orders:read")
            .AddRole("editor", "orders:write")
            .IncludeRole("editor", "reader")
            .BuildRoles();

        var editor = registry.PermissionsFor("editor");

        Assert.Equal(2, editor.Count);
        Assert.Contains("orders:read", editor);
        Assert.Contains("orders:write", editor);
    }

    [Fact]
    public void Inclusion_is_transitive_across_three_levels()
    {
        var registry = new OrionGrantBuilder()
            .AddRole("a", "a:perm")
            .AddRole("b", "b:perm")
            .AddRole("c", "c:perm")
            .IncludeRole("a", "b")
            .IncludeRole("b", "c")
            .BuildRoles();

        var a = registry.PermissionsFor("a");

        Assert.Equal(3, a.Count);
        Assert.Contains("a:perm", a);
        Assert.Contains("b:perm", a);
        Assert.Contains("c:perm", a);
    }

    [Fact]
    public void Inclusion_does_not_leak_upward_from_included_to_including_role()
    {
        var registry = new OrionGrantBuilder()
            .AddRole("reader", "orders:read")
            .AddRole("editor", "orders:write")
            .IncludeRole("editor", "reader")
            .BuildRoles();

        // editor includes reader, but reader must not gain editor's permissions.
        var reader = registry.PermissionsFor("reader");

        Assert.Single(reader);
        Assert.Contains("orders:read", reader);
        Assert.DoesNotContain("orders:write", reader);
    }

    [Fact]
    public void Diamond_inclusion_resolves_the_shared_role_once_and_unions()
    {
        var registry = new OrionGrantBuilder()
            .AddRole("base", "base:perm")
            .AddRole("left", "left:perm")
            .AddRole("right", "right:perm")
            .AddRole("top", "top:perm")
            .IncludeRole("left", "base")
            .IncludeRole("right", "base")
            .IncludeRole("top", "left", "right")
            .BuildRoles();

        var top = registry.PermissionsFor("top");

        Assert.Equal(4, top.Count);
        Assert.Contains("top:perm", top);
        Assert.Contains("left:perm", top);
        Assert.Contains("right:perm", top);
        Assert.Contains("base:perm", top);
    }

    [Fact]
    public void An_included_role_that_is_never_defined_contributes_nothing()
    {
        // "ghost" is included but never given permissions; it must resolve to nothing, not throw.
        var registry = new OrionGrantBuilder()
            .AddRole("editor", "orders:write")
            .IncludeRole("editor", "ghost")
            .BuildRoles();

        var editor = registry.PermissionsFor("editor");

        Assert.Single(editor);
        Assert.Contains("orders:write", editor);
        // The undefined included role is not promoted to a defined role.
        Assert.DoesNotContain("ghost", registry.Roles);
    }

    [Fact]
    public void IncludeRole_can_precede_AddRole_for_the_same_role()
    {
        // Declaration order must not matter: include first, then add own permissions.
        var registry = new OrionGrantBuilder()
            .IncludeRole("editor", "reader")
            .AddRole("reader", "orders:read")
            .AddRole("editor", "orders:write")
            .BuildRoles();

        var editor = registry.PermissionsFor("editor");

        Assert.Equal(2, editor.Count);
        Assert.Contains("orders:read", editor);
        Assert.Contains("orders:write", editor);
    }

    [Fact]
    public void IncludedRolesFor_reports_declared_edges_not_the_transitive_closure()
    {
        var registry = new OrionGrantBuilder()
            .AddRole("a", "a:perm")
            .AddRole("b", "b:perm")
            .AddRole("c", "c:perm")
            .IncludeRole("a", "b")
            .IncludeRole("b", "c")
            .BuildRoles();

        var aIncludes = registry.IncludedRolesFor("a");

        // a directly includes only b; c is reached transitively but is not a declared edge of a.
        Assert.Equal(["b"], aIncludes);
        Assert.Equal(["c"], registry.IncludedRolesFor("b"));
        Assert.Empty(registry.IncludedRolesFor("c"));
    }

    [Fact]
    public void IncludedRolesFor_is_empty_for_a_role_without_inclusions()
    {
        var registry = new OrionGrantBuilder()
            .AddRole("reader", "orders:read")
            .BuildRoles();

        Assert.Empty(registry.IncludedRolesFor("reader"));
    }

    [Fact]
    public void Transitive_permissions_flow_through_the_authorizer_effective_set()
    {
        using var diag = new GrantDiagnostics();
        var authorizer = Build(diag, b => b
            .AddRole("reader", "orders:read")
            .AddRole("editor", "orders:write")
            .IncludeRole("editor", "reader"));
        var principal = new GrantPrincipal { Subject = "u1", Roles = ["editor"] };

        var effective = authorizer.EffectivePermissions(principal);

        Assert.Contains("orders:read", effective);
        Assert.Contains("orders:write", effective);
        Assert.True(authorizer.Authorize(principal, "orders:read").IsGranted);
        Assert.True(authorizer.Authorize(principal, "orders:write").IsGranted);
    }

    [Fact]
    public void Repeated_inclusion_of_the_same_role_is_idempotent()
    {
        var registry = new OrionGrantBuilder()
            .AddRole("reader", "orders:read")
            .AddRole("editor", "orders:write")
            .IncludeRole("editor", "reader")
            .IncludeRole("editor", "reader")
            .BuildRoles();

        Assert.Equal(["reader"], registry.IncludedRolesFor("editor"));
        Assert.Equal(2, registry.PermissionsFor("editor").Count);
    }

    [Fact]
    public void IncludeRole_ignores_null_and_empty_included_role_names()
    {
        var registry = new OrionGrantBuilder()
            .AddRole("editor", "orders:write")
            .AddRole("reader", "orders:read")
            .IncludeRole("editor", "", null!, "reader")
            .BuildRoles();

        Assert.Equal(["reader"], registry.IncludedRolesFor("editor"));
        Assert.Equal(2, registry.PermissionsFor("editor").Count);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void IncludeRole_throws_when_role_name_is_null_or_empty(string? role)
    {
        var builder = new OrionGrantBuilder();

        Assert.ThrowsAny<ArgumentException>(() => builder.IncludeRole(role!, "reader"));
    }

    [Fact]
    public void IncludeRole_throws_when_included_roles_array_is_null()
    {
        var builder = new OrionGrantBuilder();

        Assert.Throws<ArgumentNullException>(() => builder.IncludeRole("editor", null!));
    }

    [Fact]
    public void A_direct_self_inclusion_is_a_cycle_and_throws_at_build_time()
    {
        var builder = new OrionGrantBuilder()
            .AddRole("a", "a:perm")
            .IncludeRole("a", "a");

        var ex = Assert.Throws<RoleInclusionCycleException>(() => builder.BuildRoles());
        Assert.Equal(["a", "a"], ex.Cycle);
        Assert.Contains("a -> a", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_two_role_cycle_throws_at_build_time()
    {
        var builder = new OrionGrantBuilder()
            .AddRole("a", "a:perm")
            .AddRole("b", "b:perm")
            .IncludeRole("a", "b")
            .IncludeRole("b", "a");

        var ex = Assert.Throws<RoleInclusionCycleException>(() => builder.BuildRoles());

        // The cycle closes on the role it started from, so the first and last entries match.
        Assert.Equal(ex.Cycle[0], ex.Cycle[^1]);
        Assert.Contains("a", ex.Cycle);
        Assert.Contains("b", ex.Cycle);
    }

    [Fact]
    public void A_longer_cycle_throws_at_build_time_without_looping()
    {
        var builder = new OrionGrantBuilder()
            .AddRole("a", "a:perm")
            .AddRole("b", "b:perm")
            .AddRole("c", "c:perm")
            .IncludeRole("a", "b")
            .IncludeRole("b", "c")
            .IncludeRole("c", "a");

        // The assertion completing at all is the anti-infinite-loop guarantee.
        var ex = Assert.Throws<RoleInclusionCycleException>(() => builder.BuildRoles());
        Assert.Equal(ex.Cycle[0], ex.Cycle[^1]);
        Assert.Contains("a", ex.Cycle);
        Assert.Contains("b", ex.Cycle);
        Assert.Contains("c", ex.Cycle);
    }

    [Fact]
    public void A_self_inclusion_on_an_otherwise_acyclic_graph_still_throws()
    {
        var builder = new OrionGrantBuilder()
            .AddRole("a", "a:perm")
            .AddRole("b", "b:perm")
            .IncludeRole("a", "b")
            .IncludeRole("b", "b");

        var ex = Assert.Throws<RoleInclusionCycleException>(() => builder.BuildRoles());
        Assert.Equal("b", ex.Cycle[0]);
        Assert.Equal("b", ex.Cycle[^1]);
    }

    [Fact]
    public void An_acyclic_graph_that_revisits_a_node_by_two_paths_does_not_false_positive()
    {
        // top -> left -> base and top -> right -> base revisit base, but that is a diamond, not a
        // cycle: building must succeed.
        var registry = new OrionGrantBuilder()
            .AddRole("base", "base:perm")
            .AddRole("left", "left:perm")
            .AddRole("right", "right:perm")
            .AddRole("top", "top:perm")
            .IncludeRole("left", "base")
            .IncludeRole("right", "base")
            .IncludeRole("top", "left", "right")
            .BuildRoles();

        Assert.Equal(4, registry.PermissionsFor("top").Count);
    }

    [Fact]
    public void No_inclusions_leaves_the_plain_role_map_unchanged()
    {
        // The fast path (no IncludeRole calls) must still expose roles exactly as declared.
        var registry = new OrionGrantBuilder()
            .AddRole("reader", "orders:read")
            .AddRole("writer", "orders:write")
            .BuildRoles();

        Assert.Equal(["reader", "writer"], registry.Roles.OrderBy(n => n, StringComparer.Ordinal));
        Assert.Empty(registry.IncludedRolesFor("reader"));
    }
}

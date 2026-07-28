// NativeAOT smoke test. Publishing this with PublishAot=true must produce zero trim/AOT warnings,
// and running it must exit 0 - OrionGrant's AOT exit criterion. Runtime checks, not a framework:
// the point is to prove authorization (grant, deny, deny-overrides-allow) survives trimming natively.
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionGrant;

var services = new ServiceCollection();
services.AddOrionGrant();

using var provider = services.BuildServiceProvider();
var authorizer = provider.GetRequiredService<IGrantAuthorizer>();

var principal = new GrantPrincipal { Subject = "user-1", Permissions = ["orders:read"] };
Check(authorizer.Authorize(principal, "orders:read").IsGranted, "a held permission should be granted");
Check(!authorizer.Authorize(principal, "orders:write").IsGranted, "an absent permission should be denied");

var denied = new GrantPrincipal { Subject = "user-2", Permissions = ["orders:read"], Denies = ["orders:read"] };
Check(!authorizer.Authorize(denied, "orders:read").IsGranted, "a deny should override an allow");

Console.WriteLine("OrionGrant AOT smoke test passed.");
return 0;

static void Check(bool condition, string message)
{
    if (!condition)
    {
        Console.Error.WriteLine($"AOT smoke test failed: {message}");
        Environment.Exit(1);
    }
}

namespace Moongazing.OrionGrant.Permissions;

/// <summary>
/// A bounded, thread-safe least-recently-used cache of principals' effective grant sets. Keyed on
/// principal role/permission/deny membership (see <see cref="PrincipalGrantKey"/>), so a principal
/// whose membership changes computes a different key and never serves a stale entry; the bound caps
/// memory under unbounded distinct principals by evicting the least recently used entry on overflow.
/// </summary>
/// <remarks>
/// Correctness rests on the key, not on invalidation: because role contents are fixed at build time
/// (the <see cref="RoleRegistry"/> is immutable) and the principal's own membership is part of the
/// key, a cached entry can only ever match a principal whose effective set is identical to the one
/// stored. There is therefore nothing to invalidate on a "role change": a different role set is a
/// different key. The cache is scoped to one authorizer/registry; replacing the registry means a new
/// authorizer with a fresh cache.
/// </remarks>
public sealed class BoundedEffectiveGrantCache : IEffectiveGrantCache
{
    /// <summary>The default capacity when none is specified.</summary>
    public const int DefaultCapacity = 1024;

    private readonly int capacity;
    private readonly object gate = new();

    // A dictionary for O(1) lookup paired with a recency list whose front is most-recently-used.
    // The dictionary maps a key to its node so a hit can move that node to the front in O(1).
    private readonly Dictionary<PrincipalGrantKey, LinkedListNode<Entry>> map;
    private readonly LinkedList<Entry> recency = new();

    /// <summary>Create a cache with the given capacity.</summary>
    /// <param name="capacity">
    /// The maximum number of distinct principal grant sets retained. Must be positive. Defaults to
    /// <see cref="DefaultCapacity"/>.
    /// </param>
    public BoundedEffectiveGrantCache(int capacity = DefaultCapacity)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);
        this.capacity = capacity;
        map = new Dictionary<PrincipalGrantKey, LinkedListNode<Entry>>(capacity);
    }

    /// <summary>The configured maximum number of cached entries.</summary>
    public int Capacity => capacity;

    /// <summary>The current number of cached entries.</summary>
    public int Count
    {
        get
        {
            lock (gate)
            {
                return map.Count;
            }
        }
    }

    /// <inheritdoc />
    public EffectiveGrantSet GetOrAdd(
        GrantPrincipal principal,
        Func<GrantPrincipal, EffectiveGrantSet> factory)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(factory);

        var key = PrincipalGrantKey.For(principal);

        lock (gate)
        {
            if (map.TryGetValue(key, out var existing))
            {
                // Hit: promote to most-recently-used and return the stored set.
                recency.Remove(existing);
                recency.AddFirst(existing);
                return existing.Value.Set;
            }
        }

        // Miss: build outside the lock so a slow factory does not serialize the whole cache. The
        // factory is pure for a given principal, so a benign race (two threads building the same
        // key) yields equal sets; the second insert simply replaces the first.
        var set = factory(principal);

        lock (gate)
        {
            if (map.TryGetValue(key, out var racedIn))
            {
                recency.Remove(racedIn);
                recency.AddFirst(racedIn);
                return racedIn.Value.Set;
            }

            var node = new LinkedListNode<Entry>(new Entry(key, set));
            recency.AddFirst(node);
            map[key] = node;

            if (map.Count > capacity)
            {
                var lru = recency.Last;
                if (lru is not null)
                {
                    recency.RemoveLast();
                    map.Remove(lru.Value.Key);
                }
            }

            return set;
        }
    }

    private readonly struct Entry
    {
        internal Entry(PrincipalGrantKey key, EffectiveGrantSet set)
        {
            Key = key;
            Set = set;
        }

        internal PrincipalGrantKey Key { get; }

        internal EffectiveGrantSet Set { get; }
    }
}

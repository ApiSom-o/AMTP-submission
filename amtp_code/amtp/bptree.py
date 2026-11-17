"""B+ Search Tree T^S_i (Phase 2, Step 2): protected search key h_w -> posting state.

Order B: an internal node has at most B children, a leaf at most B-1 entries; every node except
the root is at least half full. Leaves are linked (next / prev) for ordered scans and for the
predecessor of an absent key. The tree only speeds up lookup; it is never evidence: the user
checks postings against the PAPC / IMT commitments.

The class offers the dict operations the engine and the server use (get, setdefault, pop,
[] / in / len, items, keys) plus predecessor(key).
"""
from bisect import bisect_left, bisect_right

_MISSING = object()


class _Leaf:
    __slots__ = ("keys", "vals", "next", "prev")

    def __init__(self, keys=None, vals=None):
        self.keys, self.vals = keys or [], vals or []
        self.next = self.prev = None


class _Inner:
    __slots__ = ("keys", "kids")

    def __init__(self, keys, kids):
        self.keys, self.kids = keys, kids        # keys[i] separates kids[i] (< key) and kids[i+1] (>= key)


class BPlusTree:
    def __init__(self, order: int = 64):
        if order < 4:
            raise ValueError("order must be at least 4")
        self.order = order
        self.max_keys = order - 1                 # entries per leaf / separators per inner node
        self.min_keys = (order + 1) // 2 - 1      # ceil(order / 2) - 1
        self.root = _Leaf()
        self._n = 0

    # ------------------------------------------------------------ build
    @classmethod
    def from_sorted(cls, items, order: int = 64):
        """Bulk load from (key, value) pairs in strictly ascending key order."""
        t = cls(order)
        items = list(items)
        if any(items[i][0] >= items[i + 1][0] for i in range(len(items) - 1)):
            raise ValueError("keys must be strictly ascending")
        t._n = len(items)
        if len(items) <= t.max_keys:
            t.root = _Leaf([k for k, _ in items], [v for _, v in items])
            return t
        leaves, i = [], 0
        for size in _chunk_sizes(len(items), t.max_keys):
            part = items[i:i + size]
            i += size
            leaf = _Leaf([k for k, _ in part], [v for _, v in part])
            if leaves:
                leaves[-1].next, leaf.prev = leaf, leaves[-1]
            leaves.append(leaf)
        level = [(leaf.keys[0], leaf) for leaf in leaves]
        while len(level) > 1:
            nxt, i = [], 0
            sizes = [len(level)] if len(level) <= t.order else _chunk_sizes(len(level), t.order)
            for size in sizes:
                group = level[i:i + size]
                i += size
                nxt.append((group[0][0], _Inner([k for k, _ in group[1:]], [n for _, n in group])))
            level = nxt
        t.root = level[0][1]
        return t

    # ------------------------------------------------------------ lookup
    def _leaf_for(self, key):
        node, path = self.root, []
        while isinstance(node, _Inner):
            i = bisect_right(node.keys, key)
            path.append((node, i))
            node = node.kids[i]
        return node, path

    def get(self, key, default=None):
        leaf, _ = self._leaf_for(key)
        i = bisect_left(leaf.keys, key)
        if i < len(leaf.keys) and leaf.keys[i] == key:
            return leaf.vals[i]
        return default

    search = get

    def __contains__(self, key):
        return self.get(key, _MISSING) is not _MISSING

    def __getitem__(self, key):
        v = self.get(key, _MISSING)
        if v is _MISSING:
            raise KeyError(key)
        return v

    def __len__(self):
        return self._n

    def __bool__(self):
        return self._n > 0

    def predecessor(self, key):
        """Largest stored key strictly below `key`, or None."""
        leaf, _ = self._leaf_for(key)
        i = bisect_left(leaf.keys, key)
        if i:
            return leaf.keys[i - 1]
        leaf = leaf.prev
        while leaf is not None and not leaf.keys:
            leaf = leaf.prev
        return leaf.keys[-1] if leaf is not None else None

    def items(self):
        leaf = self.root
        while isinstance(leaf, _Inner):
            leaf = leaf.kids[0]
        while leaf is not None:
            yield from zip(leaf.keys, leaf.vals)
            leaf = leaf.next

    def keys(self):
        return (k for k, _ in self.items())

    __iter__ = keys

    def values(self):
        return (v for _, v in self.items())

    # ------------------------------------------------------------ insert
    def __setitem__(self, key, value):
        self.insert(key, value)

    def insert(self, key, value):
        """Insert or replace."""
        leaf, path = self._leaf_for(key)
        i = bisect_left(leaf.keys, key)
        if i < len(leaf.keys) and leaf.keys[i] == key:
            leaf.vals[i] = value
            return
        leaf.keys.insert(i, key)
        leaf.vals.insert(i, value)
        self._n += 1
        if len(leaf.keys) > self.max_keys:
            self._split_leaf(leaf, path)

    def setdefault(self, key, default=None):
        leaf, path = self._leaf_for(key)
        i = bisect_left(leaf.keys, key)
        if i < len(leaf.keys) and leaf.keys[i] == key:
            return leaf.vals[i]
        leaf.keys.insert(i, key)
        leaf.vals.insert(i, default)
        self._n += 1
        if len(leaf.keys) > self.max_keys:
            self._split_leaf(leaf, path)
        return default

    def _split_leaf(self, leaf, path):
        mid = len(leaf.keys) // 2
        right = _Leaf(leaf.keys[mid:], leaf.vals[mid:])
        del leaf.keys[mid:], leaf.vals[mid:]
        right.next, right.prev = leaf.next, leaf
        if leaf.next is not None:
            leaf.next.prev = right
        leaf.next = right
        self._insert_up(path, right.keys[0], right)

    def _insert_up(self, path, sep, right):
        while path:
            node, i = path.pop()
            node.keys.insert(i, sep)
            node.kids.insert(i + 1, right)
            if len(node.keys) <= self.max_keys:
                return
            mid = len(node.keys) // 2
            sep = node.keys[mid]
            right = _Inner(node.keys[mid + 1:], node.kids[mid + 1:])
            del node.keys[mid:], node.kids[mid + 1:]
        self.root = _Inner([sep], [self.root, right])

    # ------------------------------------------------------------ delete
    def __delitem__(self, key):
        if not self.delete(key):
            raise KeyError(key)

    def pop(self, key, default=_MISSING):
        v = self.get(key, _MISSING)
        if v is _MISSING:
            if default is _MISSING:
                raise KeyError(key)
            return default
        self.delete(key)
        return v

    def delete(self, key) -> bool:
        leaf, path = self._leaf_for(key)
        i = bisect_left(leaf.keys, key)
        if i == len(leaf.keys) or leaf.keys[i] != key:
            return False
        del leaf.keys[i], leaf.vals[i]
        self._n -= 1
        if path and len(leaf.keys) < self.min_keys:
            self._fix_leaf(leaf, path)
        return True

    def _fix_leaf(self, leaf, path):
        parent, ci = path[-1]
        left = parent.kids[ci - 1] if ci > 0 else None
        right = parent.kids[ci + 1] if ci + 1 < len(parent.kids) else None
        if left is not None and len(left.keys) > self.min_keys:
            leaf.keys.insert(0, left.keys.pop())
            leaf.vals.insert(0, left.vals.pop())
            parent.keys[ci - 1] = leaf.keys[0]
        elif right is not None and len(right.keys) > self.min_keys:
            leaf.keys.append(right.keys.pop(0))
            leaf.vals.append(right.vals.pop(0))
            parent.keys[ci] = right.keys[0]
        elif left is not None:
            self._merge_leaves(left, leaf)
            del parent.keys[ci - 1], parent.kids[ci]
            self._fix_inner(path[:-1])
        else:
            self._merge_leaves(leaf, right)
            del parent.keys[ci], parent.kids[ci + 1]
            self._fix_inner(path[:-1])

    @staticmethod
    def _merge_leaves(a, b):
        """Move b's entries into a and unlink b."""
        a.keys += b.keys
        a.vals += b.vals
        a.next = b.next
        if b.next is not None:
            b.next.prev = a

    def _fix_inner(self, path):
        """The last node of `path`'s parent chain lost a child; restore its occupancy."""
        node = self.root if not path else path[-1][0].kids[path[-1][1]]
        if node is self.root:
            if isinstance(node, _Inner) and not node.keys:
                self.root = node.kids[0]
            return
        if len(node.keys) >= self.min_keys:
            return
        parent, ci = path[-1]
        left = parent.kids[ci - 1] if ci > 0 else None
        right = parent.kids[ci + 1] if ci + 1 < len(parent.kids) else None
        if left is not None and len(left.keys) > self.min_keys:
            node.keys.insert(0, parent.keys[ci - 1])
            node.kids.insert(0, left.kids.pop())
            parent.keys[ci - 1] = left.keys.pop()
        elif right is not None and len(right.keys) > self.min_keys:
            node.keys.append(parent.keys[ci])
            node.kids.append(right.kids.pop(0))
            parent.keys[ci] = right.keys.pop(0)
        elif left is not None:
            left.keys += [parent.keys[ci - 1]] + node.keys
            left.kids += node.kids
            del parent.keys[ci - 1], parent.kids[ci]
            self._fix_inner(path[:-1])
        else:
            node.keys += [parent.keys[ci]] + right.keys
            node.kids += right.kids
            del parent.keys[ci], parent.kids[ci + 1]
            self._fix_inner(path[:-1])

    # ------------------------------------------------------------ checks
    def check(self):
        """Structural invariants (tests): balanced depth, occupancy, order, separators, leaf links."""
        depths, count = set(), 0

        def walk(node, lo, hi, depth, is_root):
            nonlocal count
            assert all(node.keys[i] < node.keys[i + 1] for i in range(len(node.keys) - 1))
            assert all((lo is None or k >= lo) and (hi is None or k < hi) for k in node.keys)
            if not is_root:
                assert self.min_keys <= len(node.keys) <= self.max_keys, len(node.keys)
            if isinstance(node, _Leaf):
                assert len(node.keys) == len(node.vals)
                depths.add(depth)
                count += len(node.keys)
                return
            assert len(node.kids) == len(node.keys) + 1 and node.keys
            bounds = [lo] + node.keys + [hi]
            for j, kid in enumerate(node.kids):
                walk(kid, bounds[j], bounds[j + 1], depth + 1, False)

        walk(self.root, None, None, 0, True)
        assert len(depths) <= 1 and count == self._n
        scanned = [k for k, _ in self.items()]
        assert scanned == sorted(scanned) and len(scanned) == self._n
        return True


def _chunk_sizes(n, max_size):
    """Split n into the fewest chunks of at most max_size, as even as possible (each at least half full)."""
    k = -(-n // max_size)
    base, extra = divmod(n, k)
    return [base + 1] * extra + [base] * (k - extra)

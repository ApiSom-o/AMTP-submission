"""Partition policies: the ONLY thing that differs between AMTP and its ablations.

  AMTP       occupancy-driven split/merge (report eq. 31-36)
  Static-MT  the same placement rule, but partitions never split or merge
  Global-MT  one partition for the whole domain (no partitioning at all)

Placement (where a new file goes) is not fixed by the report. Here every file
carries a workload "bucket" (e.g. mailbox owner) and goes to an active partition
that serves its bucket, chosen by one of two rules (the same rule for every variant):

  least  the least occupied partition (ties: smaller PID). Spreads a batch of b
         inserts over up to b partitions.
  fill   fill first: the fullest partition with n < θ_max (ties: smaller PID); if
         every partition of the bucket is full, the fullest one anyway, and split
         repairs it when the epoch commits (Static-MT never splits, so there it
         keeps growing). A batch of b inserts touches about b / θ_max partitions
         per bucket instead of b.

The rule is only the Cloud Server's choice: the Validator takes the proposed
location from the server and checks everything that follows from it, so the rule
changes no check and no proof.
"""

PLACEMENTS = ("least", "fill")


class AdaptivePolicy:
    name = "AMTP"
    versioned = True

    def __init__(self, buckets: int, theta_min: int, theta_max: int, placement: str = "least"):
        if not (0 < theta_min and 2 * theta_min < theta_max):
            raise ValueError("need 0 < θ_min and 2·θ_min < θ_max")
        if placement not in PLACEMENTS:
            raise ValueError(f"placement must be one of {PLACEMENTS}, not {placement!r}")
        self.buckets, self.theta_min, self.theta_max = buckets, theta_min, theta_max
        self.placement = placement

    def initial_lineages(self):
        return [{b} for b in range(self.buckets)]

    def place(self, eng, bucket):
        """One pass over the partitions of the bucket (O(partitions in the bucket), as before)."""
        pids, live = eng.by_bucket[bucket], eng.live
        if self.placement == "least":
            return min(pids, key=lambda pid: (live[pid], pid))
        fullest = lambda pid: (-live[pid], pid)                       # noqa: E731
        best = min((pid for pid in pids if live[pid] < self.theta_max), key=fullest, default=None)
        return best if best is not None else min(pids, key=fullest)

    def adapt(self, eng, touched):
        """Split if n > θ_max; merge if n < θ_min and a partner with
        n_j + n_k <= θ_max exists (partner = smallest (n, PID))."""
        splits = merges = 0
        queue, merged = list(touched), set()
        while queue:
            pid = queue.pop(0)
            if pid not in eng.parts or pid in merged:
                continue
            n = eng.live[pid]
            if n > self.theta_max:
                queue.extend(eng.split(pid))   # a large batch may need repeated splits
                splits += 1
            elif n < self.theta_min:
                partners = [k for k in eng.parts
                            if k != pid and n + eng.live[k] <= self.theta_max]
                if partners:
                    b = min(partners, key=lambda k: (eng.live[k], k))
                    merged.add(eng.merge(pid, b))   # not re-merged in the same transition
                    merges += 1
        return splits, merges


class StaticPolicy(AdaptivePolicy):
    """Same as AMTP but frozen: load with AdaptivePolicy, then switch to this one,
    so both variants start from the identical partition layout."""
    name = "Static-MT"

    def adapt(self, eng, touched):
        return 0, 0


class GlobalPolicy:
    """One partition for everything. With a single partition the version number
    adds no binding (R_D already fixes the one partition root), so by default it
    is not bumped; versioned=True gives the literal 'AMTP with one partition'."""
    name = "Global-MT"

    def __init__(self, buckets: int, versioned: bool = False):
        self.buckets, self.versioned = buckets, versioned
        if versioned:
            self.name = "Global-MT(v)"

    def initial_lineages(self):
        return [set(range(self.buckets))]

    def place(self, eng, bucket):
        return next(iter(eng.by_bucket[bucket]))

    def adapt(self, eng, touched):
        return 0, 0

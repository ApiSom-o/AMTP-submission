"""Root Anchor (RA): stand-in for the smart contract that stores finalized roots.

It accepts a new Domain Root only if
  * the owner's signature on the transition is valid, and
  * the epoch is exactly e* + 1 and the predecessor root matches,
then recomputes the Global Root R_G over all current Domain Roots.
The prototype would deploy this logic as a Solidity contract on a local chain.
"""
from dataclasses import dataclass

from .core.crypto import sig_ok
from .core.hashing import H, TAG_TRANSITION, lp
from .core.merkle import merkle_root


NO_DELTA = b"\x00" * 32


def transition_message(domain, epoch, r_d: bytes, prev: bytes, delta: bytes = NO_DELTA) -> bytes:
    """σ_root is a signature on H(i ‖ e' ‖ R^(e) ‖ R^(e') ‖ Δ) (eq. 29); this is its length-prefixed,
    tagged preimage. Δ is the AUDC of the validated transition."""
    return lp(TAG_TRANSITION, domain, epoch, prev, r_d, delta)


@dataclass
class AnchorEntry:
    domain: str
    epoch: int
    R_D: bytes
    R_G: bytes
    block: int
    delta: bytes = NO_DELTA


class RootAnchor:
    def __init__(self):
        self.owners = {}      # domain -> owner public key
        self.current = {}     # domain -> (epoch, R_D)
        self.history = []     # every accepted transition
        self.R_G = merkle_root([])
        self.block = 0

    def register_domain(self, domain, owner_public_key, r0: bytes):
        """Setup (eq. 1): record the root-update key and the genesis root (R^(0), e* = 0)."""
        if domain in self.current:
            raise ValueError("domain already registered")
        self.owners[domain] = owner_public_key
        self.current[domain] = (0, r0)
        self._global()

    def submit(self, domain, epoch, r_d: bytes, sig: bytes, delta: bytes = NO_DELTA, prev: bytes = None):
        """Atomic transition: the predecessor (if given) must be the current root, e' = e* + 1, and
        σ_root must verify on (i, e', R^(e*), R^(e'), Δ)."""
        e_star, current = self.current[domain]
        if prev is not None and prev != current:
            raise ValueError("predecessor root is not the current anchored root")
        if epoch != e_star + 1:
            raise ValueError(f"epoch must be {e_star + 1}, got {epoch}")
        if not sig_ok(self.owners[domain], transition_message(domain, epoch, r_d, current, delta), sig):
            raise ValueError("owner signature invalid")
        self.current[domain] = (epoch, r_d)
        self._global()
        self.block += 1
        self.history.append(AnchorEntry(domain, epoch, r_d, self.R_G, self.block, delta))

    def _global(self):
        self.R_G = merkle_root([H(d, e, r) for d, (e, r) in sorted(self.current.items())])

    def latest(self, domain):
        """What a Data User reads: (e*, R_D^(e*))."""
        return self.current[domain]

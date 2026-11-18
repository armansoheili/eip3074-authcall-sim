"""EIP-3074 AUTH / AUTHCALL simulator in pure Python.

EIP-3074 lets an EOA delegate control of its account to an *invoker*
contract for a single transaction: the EOA signs an authorization, the
invoker calls ``AUTH`` to prove it, and then ``AUTHCALL`` lets the invoker
spend the EOA's ETH and call other contracts *as* the EOA. The invoker
pays the gas, so the EOA never needs ETH for fees -- sponsored transactions.

This module is a self-contained simulation (no dependencies, no network):

* self-contained Keccak-256 and secp256k1 (sign / ecrecover)
* EIP-55 checksummed addresses
* ``authorize()`` builds the EIP-3074 signature over
  ``commit = keccak256(0x03 || chain_id || nonce || invoker)``
* ``Chain`` models EOAs, a contract registry, and the per-transaction
  AUTH frame: authorization is set by AUTH, usable by AUTHCALL, and
  cleared when the transaction ends

Run the demo: ``python3 eip3074.py --demo``
Run the tests: ``python3 eip3074.py --test`` (doctests)

>>> keccak256(b"").hex()
'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
>>> keccak256(b"abc").hex()
'4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'
>>> pubkey_to_address(privkey_to_pubkey(1))
'0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf'
"""

import argparse
import doctest
import hashlib
import hmac
import sys

# ---------------------------------------------------------------------------
# Keccak-256 (self-contained, no dependencies)
# ---------------------------------------------------------------------------

_MASK = (1 << 64) - 1

_ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# Rotation offsets r[x][y] from the Keccak spec.
_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rol(x, n):
    return ((x << n) | (x >> (64 - n))) & _MASK if n else x & _MASK


def _keccak_f(state):
    for rc in _ROUND_CONSTANTS:
        # Theta
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        # Rho and Pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(state[x + 5 * y], _ROT[x][y])
        # Chi
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = (b[x + 5 * y]
                                    ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]))
        # Iota
        state[0] ^= rc
    return state


def keccak256(data):
    """Keccak-256 digest of ``data`` (Ethereum's hash function)."""
    rate = 136  # bytes absorbed per block for a 256-bit output
    state = [0] * 25
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate:
        padded.append(0x00)
    padded[-1] |= 0x80
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        _keccak_f(state)
    return b"".join(state[i].to_bytes(8, "little") for i in range(4))


# ---------------------------------------------------------------------------
# secp256k1 (sign / ecrecover) and EIP-55 addresses
# ---------------------------------------------------------------------------

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _inv(a, m):
    return pow(a, -1, m)


def _point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p == q:
        lam = (3 * x1 * x1) * _inv(2 * y1, _P) % _P
    else:
        lam = (y2 - y1) * _inv(x2 - x1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    return x3, (lam * (x1 - x3) - y1) % _P


def _scalar_mult(k, point=_G):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def privkey_to_pubkey(priv):
    """Uncompressed 64-byte public key (x || y) for a private key int."""
    x, y = _scalar_mult(priv)
    return x.to_bytes(32, "big") + y.to_bytes(32, "big")


def pubkey_to_address(pubkey):
    """EIP-55 checksummed Ethereum address for a 64-byte public key."""
    raw = keccak256(pubkey)[-20:]
    return to_checksum_address(raw)


def to_checksum_address(raw20):
    """EIP-55 checksum encoding of a 20-byte address (or 0x-prefixed hex)."""
    if isinstance(raw20, str):
        raw20 = bytes.fromhex(raw20[2:] if raw20.startswith("0x") else raw20)
    hex_addr = raw20.hex()
    digest = keccak256(hex_addr.encode()).hex()
    return "0x" + "".join(
        ch.upper() if int(digest[i], 16) >= 8 else ch
        for i, ch in enumerate(hex_addr))


def _rfc6979_k(priv, msg_hash):
    """Deterministic nonce (RFC 6979, HMAC-SHA256) for signing."""
    x = priv.to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + msg_hash, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + msg_hash, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < _N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign_digest(priv, digest):
    """Sign a 32-byte digest; returns (v, r, s) with low-S and v in {27, 28}."""
    z = int.from_bytes(digest, "big")
    k = _rfc6979_k(priv, digest)
    r_point = _scalar_mult(k)
    r = r_point[0] % _N
    assert r != 0
    s = (_inv(k, _N) * (z + r * priv)) % _N
    recid = (r_point[1] & 1) | (2 if r_point[0] >= _N else 0)
    if s > _N // 2:  # low-S normalization (EIP-2)
        s = _N - s
        recid ^= 1
    return 27 + recid, r, s


def ecrecover(digest, v, r, s):
    """Recover the signer address from a digest and (v, r, s) signature."""
    recid = v - 27
    if recid not in (0, 1, 2, 3) or not (1 <= r < _N) or not (1 <= s < _N):
        raise ValueError("invalid signature")
    z = int.from_bytes(digest, "big")
    # Candidate x coordinates for R.
    x = r + (recid // 2) * _N
    if x >= _P:
        raise ValueError("invalid signature")
    alpha = (pow(x, 3, _P) + 7) % _P
    beta = pow(alpha, (_P + 1) // 4, _P)
    if pow(beta, 2, _P) != alpha:
        raise ValueError("invalid signature")
    y = beta if beta % 2 == recid % 2 else _P - beta
    r_point = (x, y)
    r_inv = _inv(r, _N)
    u1 = (-z * r_inv) % _N
    u2 = (s * r_inv) % _N
    pub = _point_add(_scalar_mult(u1), _scalar_mult(u2, r_point))
    if pub is None:
        raise ValueError("invalid signature")
    return pubkey_to_address(pub[0].to_bytes(32, "big") + pub[1].to_bytes(32, "big"))


# ---------------------------------------------------------------------------
# EIP-3074: AUTH / AUTHCALL
# ---------------------------------------------------------------------------

MAGIC = 0x03  # EIP-3074 magic byte, first byte of the signed commit


def auth_commit(chain_id, nonce, invoker):
    """EIP-3074 commit: keccak256(0x03 || chain_id || nonce || invoker).

    >>> auth_commit(1, 0, "0x0000000000000000000000000000000000000000").hex()
    '7db199bdd75085c671a05246359615edddce39a29578b7133a0d735eebe1e237'
    """
    invoker_bytes = bytes.fromhex(invoker[2:])
    return keccak256(
        bytes([MAGIC])
        + chain_id.to_bytes(32, "big")
        + nonce.to_bytes(32, "big")
        + invoker_bytes)


def authorize(priv, chain_id, nonce, invoker):
    """Sign an EIP-3074 authorization for ``invoker``; returns (v, r, s).

    The signer is the EOA; ``nonce`` is the EOA's current AUTH nonce, so
    each authorization can only be used once.
    """
    return sign_digest(priv, auth_commit(chain_id, nonce, invoker))


class Account:
    """An externally owned account: balance (wei) and AUTH nonce."""

    def __init__(self, address, balance=0):
        self.address = address
        self.balance = balance
        self.nonce = 0

    def __repr__(self):
        return f"Account({self.address}, balance={self.balance}, nonce={self.nonce})"


class SimpleStore:
    """A toy target contract: one stored uint, settable by anyone."""

    def __init__(self):
        self.address = "0x00000000000000000000000000000000DEADBEEF"
        self.value = 0

    def call(self, sender, value, data):
        """Handle a call: data is ("set", n) or ("get",)."""
        if data[0] == "set":
            self.value = data[1]
            return True, self.value
        if data[0] == "get":
            return True, self.value
        return False, "unknown function"


class Chain:
    """A minimal chain: accounts, contracts, and the per-tx AUTH frame."""

    def __init__(self, chain_id):
        self.chain_id = chain_id
        self.accounts = {}
        self.contracts = {}
        self.authorized = None  # (invoker, eoa) set by AUTH, cleared at tx end
        self.log = []

    def add_account(self, address, balance=0):
        self.accounts[address] = Account(address, balance)
        return self.accounts[address]

    def add_contract(self, contract):
        self.contracts[contract.address] = contract

    # -- transaction frame -------------------------------------------------
    def begin_tx(self, invoker):
        """Start a transaction sent by ``invoker`` (the gas payer)."""
        if self.authorized is not None:
            raise RuntimeError("transaction already in progress")
        self.tx_invoker = invoker
        self.log.append(f"tx begins (invoker {invoker})")

    def end_tx(self):
        """End the transaction: AUTH authorization is wiped (EIP-3074)."""
        self.authorized = None
        self.log.append("tx ends (authorization cleared)")

    # -- AUTH --------------------------------------------------------------
    def auth(self, eoa_address, invoker, v, r, s):
        """AUTH: verify the EOA's signature and authorize ``invoker``.

        Returns True on success. Consumes the EOA's AUTH nonce, so the
        same signature can never be replayed -- not even on another chain,
        since chain_id is inside the signed commit.

        >>> chain = Chain(1)
        >>> alice = chain.add_account(pubkey_to_address(privkey_to_pubkey(1)), 10**18)
        >>> invoker = "0x1111111111111111111111111111111111111111"
        >>> chain.begin_tx(invoker)
        >>> chain.auth(alice.address, invoker, *authorize(1, 1, 0, invoker))
        True
        >>> alice.nonce
        1
        >>> chain.end_tx()
        """
        eoa = self.accounts.get(eoa_address)
        if eoa is None:
            return False
        if invoker != self.tx_invoker:
            return False
        try:
            signer = ecrecover(auth_commit(self.chain_id, eoa.nonce, invoker), v, r, s)
        except ValueError:
            return False
        if signer != eoa_address:
            return False
        eoa.nonce += 1
        self.authorized = (invoker, eoa_address)
        self.log.append(f"AUTH ok: {eoa_address} authorized {invoker}")
        return True

    # -- AUTHCALL ----------------------------------------------------------
    def authcall(self, invoker, target, value, data):
        """AUTHCALL: the authorized invoker calls ``target`` as the EOA.

        ``value`` wei moves from the EOA's balance to the target (contract
        or plain address). Returns (success, return_data).

        >>> chain = Chain(1)
        >>> alice = chain.add_account(pubkey_to_address(privkey_to_pubkey(1)), 10**18)
        >>> store = SimpleStore(); chain.add_contract(store)
        >>> invoker = "0x1111111111111111111111111111111111111111"
        >>> chain.begin_tx(invoker)
        >>> chain.auth(alice.address, invoker, *authorize(1, 1, 0, invoker))
        True
        >>> chain.authcall(invoker, store.address, 0, ("set", 42))
        (True, 42)
        >>> store.value
        42
        >>> chain.end_tx()
        """
        if self.authorized is None or self.authorized[0] != invoker:
            self.log.append("AUTHCALL rejected: invoker not authorized")
            return False, "not authorized"
        eoa_address = self.authorized[1]
        eoa = self.accounts[eoa_address]
        if value > eoa.balance:
            self.log.append("AUTHCALL rejected: insufficient balance")
            return False, "insufficient balance"
        eoa.balance -= value
        contract = self.contracts.get(target)
        if contract is not None:
            success, ret = contract.call(eoa_address, value, data)
        else:
            # Plain address: a simple value transfer.
            recipient = self.accounts.get(target)
            if recipient is not None:
                recipient.balance += value
            success, ret = True, value
        self.log.append(
            f"AUTHCALL: {invoker} called {target} as {eoa_address} "
            f"(value {value}, success {success})")
        return success, ret


def demo():
    """Sponsored transaction: a relayer pays gas, Alice's EOA pays the call."""
    alice_priv = 1
    alice = pubkey_to_address(privkey_to_pubkey(alice_priv))
    invoker = "0x1111111111111111111111111111111111111111"
    bob = "0x2222222222222222222222222222222222222222"

    chain = Chain(chain_id=1)
    chain.add_account(alice, balance=10**18)  # Alice holds 1 ETH, no gas needed
    chain.add_account(bob, balance=0)
    store = SimpleStore()
    chain.add_contract(store)

    print("Alice (EOA):", alice)
    print("Invoker (relayer, pays gas):", invoker)
    print("Alice authorizes the invoker off-chain (nonce 0)...")
    sig = authorize(alice_priv, chain.chain_id, 0, invoker)

    chain.begin_tx(invoker)
    print("AUTH:", chain.auth(alice, invoker, *sig))
    print("AUTHCALL set(42):", chain.authcall(invoker, store.address, 0, ("set", 42)))
    print("AUTHCALL send 0.1 ETH to Bob:",
          chain.authcall(invoker, bob, 10**17, ()))
    print("store value:", store.value)
    print("Bob balance:", chain.accounts[bob].balance)
    chain.end_tx()

    print("\nReplay attack: same signature, same nonce...")
    chain.begin_tx(invoker)
    print("AUTH (replayed):", chain.auth(alice, invoker, *sig))
    print("AUTHCALL after failed AUTH:", chain.authcall(invoker, store.address, 0, ("set", 7)))
    chain.end_tx()

    print("\nWrong-chain authorization (signed for chain 1, replayed on 137)...")
    other = Chain(chain_id=137)
    other.add_account(alice, balance=10**18)
    other.begin_tx(invoker)
    print("AUTH on chain 137:", other.auth(alice, invoker, *sig))
    other.end_tx()

    print("\nTransaction log:")
    for entry in chain.log:
        print(" ", entry)


def main(argv=None):
    parser = argparse.ArgumentParser(description="EIP-3074 AUTH / AUTHCALL simulator")
    parser.add_argument("--demo", action="store_true", help="run the sponsored-tx demo")
    parser.add_argument("--test", action="store_true", help="run doctests")
    args = parser.parse_args(argv)
    if args.test:
        failures, _ = doctest.testmod()
        print(f"{'FAIL' if failures else 'OK'}: {failures} doctest failures")
        return 1 if failures else 0
    demo()
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""
Benchmark: list-of-keys decode vs. pre-indexed KeySet decode.

Run from the repository root:

    .venv/bin/python benchmarks/benchmark_key_set.py

It measures, over a fixed set of N v4.public keys that all share the token's
header:

  1. how many times the actual cryptographic verification primitive runs; and
  2. the wall-clock time of decoding the same token repeatedly,

for (a) a list of keys with no hint (the signer's key is placed last, so every
earlier key is tried and rejected first -- the costly order) and (b) a KeySet
using a key id hint in the footer (exactly one candidate). It finishes with a
negative control showing that a forged hint pointing at the wrong key can never
make an incorrect key verify the token.

Everything is local: no network access is performed.
"""

import json
import time

from cryptography.hazmat.primitives.asymmetric import ed25519

from pyseto import Key, KeySet, VerifyError, decode, encode

KEY_A = "tests/keys/private_key_ed25519.pem"
PUB_A = "tests/keys/public_key_ed25519.pem"
PUB_B = "tests/keys/public_key_ed25519_2.pem"
ITERATIONS = 500


def read_pem(path):
    with open(path) as handle:
        return handle.read()


def make_counting(key):
    key.calls = 0
    original_verify = key.verify

    def count_verify(payload, footer=b"", implicit_assertion=b""):
        key.calls += 1
        return original_verify(payload, footer, implicit_assertion)

    key.verify = count_verify
    return key


def distinct_public_keys(count):
    """Genuinely distinct v4.public keys, so the KeySet indexes each separately."""
    keys = []
    for _ in range(count):
        public = ed25519.Ed25519PrivateKey.generate().public_key()
        keys.append(Key.from_asymmetric_key_params(4, x=public.public_bytes_raw()))
    return keys


def main():
    signer = Key.new(4, "public", read_pem(KEY_A))
    wrong = Key.new(4, "public", read_pem(PUB_B))

    for size in (4, 16, 64):
        # The signer's key is last: without a hint the list path must verify
        # against every earlier key before reaching the one that succeeds.
        # Build independent key instances per path so the call counters never
        # overlap between the list and KeySet measurements.
        list_correct = make_counting(Key.new(4, "public", read_pem(PUB_A)))
        set_correct = make_counting(Key.new(4, "public", read_pem(PUB_A)))
        list_keys = [make_counting(k) for k in distinct_public_keys(size - 1)] + [list_correct]
        set_keys = [make_counting(k) for k in distinct_public_keys(size - 1)] + [set_correct]
        key_set = KeySet(set_keys)

        token_no_hint = encode(signer, b"benchmark-payload")
        hinted_footer = json.dumps({"kid": set_correct.to_paserk_id()}).encode()
        token_hinted = encode(signer, b"benchmark-payload", footer=hinted_footer)

        if decode(list_keys, token_no_hint).payload != b"benchmark-payload":
            raise SystemExit("list path correctness check failed")
        if decode(key_set, token_hinted).payload != b"benchmark-payload":
            raise SystemExit("KeySet path correctness check failed")

        list_before = sum(k.calls for k in list_keys)
        start = time.perf_counter()
        for _ in range(ITERATIONS):
            decode(list_keys, token_no_hint)
        list_elapsed = time.perf_counter() - start
        list_calls = sum(k.calls for k in list_keys) - list_before

        set_before = sum(k.calls for k in set_keys)
        start = time.perf_counter()
        for _ in range(ITERATIONS):
            decode(key_set, token_hinted)
        set_elapsed = time.perf_counter() - start
        set_calls = sum(k.calls for k in set_keys) - set_before

        print(f"key set size={size:3d}, iterations={ITERATIONS}")
        print(
            f"  list (no hint):  {list_calls:6d} verify calls "
            f"({list_calls / ITERATIONS:5.1f}/decode)  "
            f"{list_elapsed * 1000:9.2f} ms total"
        )
        print(
            f"  KeySet (hint):   {set_calls:6d} verify calls "
            f"({set_calls / ITERATIONS:5.1f}/decode)  "
            f"{set_elapsed * 1000:9.2f} ms total"
        )
        print(
            f"  reduction: {list_calls / set_calls:5.1f}x fewer verifications, " f"{list_elapsed / set_elapsed:5.2f}x wall time"
        )
        print()

    forged_footer = json.dumps({"kid": wrong.to_paserk_id()}).encode()
    forged_token = encode(signer, b"secret", footer=forged_footer)
    correct = Key.new(4, "public", read_pem(PUB_A))
    key_set = KeySet([correct, wrong])
    try:
        decode(key_set, forged_token)
    except VerifyError:
        print("forged-hint control: rejected with VerifyError as expected")
        return
    raise SystemExit("forged-hint control unexpectedly succeeded")


if __name__ == "__main__":
    main()

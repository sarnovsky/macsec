#!/usr/bin/env python3
"""Linux host tests: isolated full/server/client builds exchanging real frames.

Run from any directory: python3 tests/role_matrix/run.py
Requires Python 3, make, GCC-compatible cc and binutils nm. No Python packages.
All build products stay in a temporary directory. Embedded build flags are not
changed. Deterministic RNG and PN injection are restricted to this host test.
"""
import ctypes as ct
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
CC = shlex.split(os.environ.get("CC", "cc"))
SOURCES = ["macsec_common.c", "frame_crypto.c", "macsec.c", "mka.c",
           "mka_crypto.c", "math/aes.c", "math/cmac.c", "math/gcm.c"]
PROFILES = {"full": (1, 1), "server": (1, 0), "client": (0, 1)}
NOT_READY, UNSUPPORTED, REPLAY = -9, -6, -5
SECURED, SERVER, KN, AN, PN, CONFIRMED, OLD, ERROR = range(8)
BUFFER = ct.c_ubyte * 2048


def run(args, **kwargs):
    result = subprocess.run([str(a) for a in args], cwd=ROOT, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kwargs)
    if result.returncode:
        raise RuntimeError("Command failed: " + shlex.join(map(str, args)) + "\n" + result.stdout)
    return result.stdout


def flags(profile):
    server, client = PROFILES[profile]
    return [f"-DMACSEC_MKA_SERVER_SUPPORT={server}", f"-DMACSEC_MKA_CLIENT_SUPPORT={client}"]


def unit_matrix(build):
    for name in PROFILES:
        for rom in (0, 1):
            for fewer in (0, 1):
                dest = build / f"unit-{name}-{rom}-{fewer}"
                s, c = PROFILES[name]
                run(["make", "-C", "examples/unit_tests", "-j4", f"CC={shlex.join(CC)}",
                     f"BUILD_DIR={dest}", f"MACSEC_MKA_SERVER_SUPPORT={s}",
                     f"MACSEC_MKA_CLIENT_SUPPORT={c}", f"MATH_AES_ROM_TABLES={rom}",
                     f"MATH_AES_FEWER_TABLES={fewer}", "MACSEC_DEBUG_LEVEL=1",
                     "CFLAGS=-std=c99 -Wall -Wextra -Werror -O2 -MMD -MP"])
                output = run([dest / "macsec_tests"])
                if "ALL TESTS OK" not in output:
                    raise AssertionError(output)
                print(f"PASS unit {name}: ROM={rom} FEWER={fewer}", flush=True)


def compile_profiles(build):
    libraries = {}
    base = CC + ["-std=c99", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT),
                 "-DMACSEC_SELF_TEST=0", "-DMACSEC_DEBUG_LEVEL=0", "-DMATH_AES_ROM_TABLES"]
    for name in PROFILES:
        # O0 inspection proves that preprocessor removal, not optimization or
        # linker garbage collection, removes the disabled private engines.
        symbols = ""
        for source in ("mka.c", "mka_crypto.c", "math/aes.c", "macsec.c"):
            obj = build / (name + "-" + source.replace("/", "-") + ".o")
            run(base + flags(name) + ["-O0", "-c", source, "-o", obj])
            symbols += run(["nm", "--defined-only", obj])
        present = {line.split()[-1] for line in symbols.splitlines() if line.split()}
        server_symbols = {"macsec_mka_start_rekey", "macsec_mka_key_server_ensure_sak",
                          "macsec_mka_write_distributed_sak", "macsec_check_mka_pn_lifetime",
                          "macsec_mka_aes_kw_wrap"}
        client_symbols = {"math_aes_setdeckey", "math_aes_decrypt", "REVERSE_S_BOX",
                          "REVERSE_TABLES_0", "macsec_mka_aes_kw_unwrap"}
        if name == "client":
            assert not (present & server_symbols), present & server_symbols
        else:
            assert server_symbols <= present, server_symbols - present
        if name == "server":
            assert not (present & client_symbols), present & client_symbols
        else:
            assert client_symbols <= present, client_symbols - present
        library = build / (name + ".so")
        run(base + flags(name) + ["-O2", "-fPIC", "-shared", "-fvisibility=hidden",
            "-DMACSEC_REKEY_PN_THRESHOLD=4096u"] + SOURCES +
            ["port/embedded/port.c", "tests/role_matrix/endpoint.c", "-o", library])
        libraries[name] = Library(library)
        print(f"PASS production {name}: build and disabled-symbol checks", flush=True)
    for s, c in ((0, 0), (2, 1), (1, -1)):
        result = subprocess.run(CC + ["-I", str(ROOT), "-x", "c", "-fsyntax-only", "-",
                            f"-DMACSEC_MKA_SERVER_SUPPORT={s}", f"-DMACSEC_MKA_CLIENT_SUPPORT={c}"],
                            input='#include "macsec_config.h"\n', text=True, capture_output=True)
        assert result.returncode != 0 and "error:" in result.stderr, (s, c, result.stderr)
    print("PASS invalid configuration rejection", flush=True)
    return libraries


class Library:
    def __init__(self, path):
        self.lib = ct.CDLL(str(path))
        ptr, uint, size = ct.c_void_p, ct.c_uint32, ct.c_size_t
        signatures = {
            "create": (ptr, [uint, uint, uint]), "destroy": (None, [ptr]),
            "tick": (ct.c_int, [ptr, uint]), "control": (ct.c_int, [ptr, ptr, size, uint]),
            "receive": (ct.c_int, [ptr, ptr, size, ptr, size]),
            "output": (ct.c_int, [ptr, ptr, size, ptr, size]),
            "value": (uint, [ptr, uint]), "set_pn": (None, [ptr, uint]),
            "key": (ct.c_int, [ptr, ptr]), "rekey": (ct.c_int, [ptr]),
        }
        for name, (result, args) in signatures.items():
            func = getattr(self.lib, "role_" + name)
            func.restype, func.argtypes = result, args
            setattr(self, name, func)


class Endpoint:
    def __init__(self, lib, identity, priority, cak_len):
        self.lib, self.identity = lib, identity
        self.ctx = lib.create(identity, priority, cak_len)
        assert self.ctx, "endpoint init failed"

    def close(self):
        self.lib.destroy(self.ctx)
        self.ctx = None

    def value(self, field):
        return self.lib.value(self.ctx, field)

    def receive(self, data):
        output = BUFFER()
        result = self.lib.receive(self.ctx, data, len(data), output, len(output))
        return result, bytes(output[:max(result, 0)])

    def key(self):
        output = BUFFER()
        size = self.lib.key(self.ctx, output)
        return bytes(output[:size])

    def traffic(self, peer):
        plain = bytes([2, 0, 0, 0, 0, peer.identity, 2, 0, 0, 0, 0, self.identity, 8, 0]) + bytes(range(82))
        output = BUFFER()
        length = self.lib.output(self.ctx, plain, len(plain), output, len(output))
        assert length > len(plain), length
        packet = bytes(output[:length])
        result, decoded = peer.receive(packet)
        assert result == len(plain) and decoded == plain, (result, len(plain))
        assert peer.receive(packet)[0] == REPLAY
        return packet


class Pair:
    def __init__(self, server_lib, client_lib, cak_len, priorities=(10, 100)):
        self.a = Endpoint(server_lib, 1, priorities[0], cak_len)
        self.b = Endpoint(client_lib, 2, priorities[1], cak_len)
        self.now = 1

    def close(self):
        self.a.close()
        self.b.close()

    def pump(self, steps=60, accept_conflict=False):
        conflicts = 0
        for _ in range(steps):
            self.now += 100
            for endpoint in (self.a, self.b):
                assert endpoint.lib.tick(endpoint.ctx, self.now) == 0
            for sender, receiver in ((self.a, self.b), (self.b, self.a)):
                output = BUFFER()
                length = sender.lib.control(sender.ctx, output, len(output), self.now)
                if length == NOT_READY:
                    continue
                assert length > 0, length
                ret, _ = receiver.receive(bytes(output[:length]))
                if accept_conflict and ret == UNSUPPORTED:
                    conflicts += 1
                else:
                    assert ret == 0, ret
            assert not self.a.value(ERROR) and not self.b.value(ERROR)
        return conflicts

    def ready(self):
        assert self.a.value(SECURED) and self.b.value(SECURED)
        assert self.a.value(SERVER) and not self.b.value(SERVER)
        assert self.a.value(CONFIRMED) and self.b.value(CONFIRMED)
        assert self.a.value(KN) == self.b.value(KN)
        assert self.a.key() == self.b.key()
        assert self.a.value(OLD) == 0 and self.b.value(OLD) == 0
        self.a.traffic(self.b)
        self.b.traffic(self.a)


def interop(libraries):
    for names in (("full", "full"), ("server", "client"), ("server", "full"), ("full", "client")):
        for cak_len in (16, 32):
            pair = Pair(libraries[names[0]], libraries[names[1]], cak_len)
            try:
                pair.pump()
                pair.ready()
                # Repeated real rekeys, including AN reuse after all four ANs.
                for sequence in range(6):
                    old_kn, old_an, old_key = pair.a.value(KN), pair.a.value(AN), pair.a.key()
                    sender = pair.a if sequence % 2 == 0 else pair.b
                    receiver = pair.b if sender is pair.a else pair.a
                    sender.lib.set_pn(sender.ctx, 4096)
                    sender.traffic(receiver)
                    pair.pump()
                    pair.ready()
                    assert pair.a.value(KN) == old_kn + 1
                    assert pair.a.value(AN) != old_an and pair.a.key() != old_key
                    assert pair.a.value(PN) < 4096 and pair.b.value(PN) < 4096
                # Same peer/key after a quiet timeout: never reset data counters.
                old_kn, old_key = pair.a.value(KN), pair.a.key()
                old_pn = (pair.a.value(PN), pair.b.value(PN))
                replay = pair.a.traffic(pair.b)
                pair.now += 7000
                for endpoint in (pair.a, pair.b):
                    assert endpoint.lib.tick(endpoint.ctx, pair.now) == 0
                    assert not endpoint.value(SECURED)
                pair.pump()
                pair.ready()
                assert pair.a.value(KN) == old_kn and pair.a.key() == old_key
                assert pair.a.value(PN) >= old_pn[0] and pair.b.value(PN) >= old_pn[1]
                assert pair.b.receive(replay)[0] == REPLAY
                # A new client MI requires a genuinely new SAK from the server.
                old_key = pair.a.key()
                pair.b.close()
                pair.b = Endpoint(libraries[names[1]], 2, 100, cak_len)
                pair.pump()
                pair.ready()
                assert pair.a.key() != old_key
                if names[1] == "client":
                    assert pair.b.lib.rekey(pair.b.ctx) == UNSUPPORTED
                print(f"PASS interop {names[0]}/{names[1]} CAK={cak_len}: data, 6 rekeys, timeout, restart", flush=True)
            finally:
                pair.close()
    for names in (("server", "server"), ("client", "client")):
        pair = Pair(libraries[names[0]], libraries[names[1]], 16)
        try:
            assert pair.pump(accept_conflict=True) > 0
            assert not pair.a.value(SECURED) and not pair.b.value(SECURED)
            print(f"PASS incompatible roles {names[0]}/{names[1]}: rejected, no secure port", flush=True)
        finally:
            pair.close()


def main():
    with tempfile.TemporaryDirectory(prefix="macsec-role-matrix-") as directory:
        build = Path(directory)
        unit_matrix(build)
        interop(compile_profiles(build))
    print("ALL ROLE MATRIX TESTS PASSED")


if __name__ == "__main__":
    main()

"""Patch the pinned X4 Pro networking dependencies after PlatformIO resolves them."""

import hashlib
import os
from pathlib import Path
import subprocess


PATCH = "wireguard_patches/0001-crosspoint-lifecycle.patch"
NETWORK_MANAGER_PATH = "libraries/Network/src/NetworkManager.cpp"
NETWORK_MANAGER_UPSTREAM = "a4c0c9c35fa185884d5acbc3c9a3e029d0fb9e4bf824d313e81b5dd4c6d5328a"
NETWORK_MANAGER_PATCHED = "1ccd9f9db9a11aa767ab8cb3c9cea22af80fee684d8b111a306cab67b5ed0f67"
TARGETS = (
    ("src/WireGuard-ESP32.h",
     "ea394257d48900a72676663c31da708ef84b3f9992375f2c3d348abcc8080537",
     "eb44fab0255ceaafa68552b25bd7cb7aebfe5d76a38e82c4098b139242b7e696"),
    ("src/WireGuard.cpp",
     "2911a5c6281571d9305df7f6b9413e5bf4052ad4ed6a187bbd62f6ab2a7d87a9",
     "510686a3e89b08565f7567f47fec9f23d6fca5902139fdd92ad5773115dabc53"),
    ("src/wireguard-platform.c",
     "b8de56243203841f71918624a8dd013150abac1295926528707d8d87744844fb",
     "2fec2f55a9a950beade8dc7bae4945a364d1c476b35a95b0dc286b3262754d48"),
    ("src/wireguardif.c",
     "e1521dff00b54e396cfb34b370c4e102e4221a5bdabd98a3762734aac39122f3",
     "0345d583613dde6de83cf6283325a4525d0ff40f811463cb1926af54b5457c5b"),
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def is_within(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def patch_network_manager(env):
    framework = Path(env.PioPlatform().get_package_dir("framework-arduinoespressif32")).resolve()
    target = (framework / NETWORK_MANAGER_PATH).resolve()
    if not is_within(target, framework) or not target.is_file():
        raise RuntimeError("Missing or escaping Arduino NetworkManager source")

    current = digest(target)
    if current == NETWORK_MANAGER_PATCHED:
        return
    if current != NETWORK_MANAGER_UPSTREAM:
        raise RuntimeError("Unrecognized Arduino NetworkManager source")

    source = target.read_text(encoding="utf-8")
    include_old = '#include "lwip/dns.h"\n'
    include_new = include_old + '#include "lwip/tcpip.h"\n'
    clear_old = "    dns_clear_cache();\n"
    clear_new = "    LOCK_TCPIP_CORE();\n" + clear_old + "    UNLOCK_TCPIP_CORE();\n"
    if source.count(include_old) != 1 or source.count(clear_old) != 1:
        raise RuntimeError("Unsupported Arduino NetworkManager DNS cache code")
    target.write_text(source.replace(include_old, include_new, 1).replace(clear_old, clear_new, 1), encoding="utf-8")
    if digest(target) != NETWORK_MANAGER_PATCHED:
        raise RuntimeError("Unexpected patched Arduino NetworkManager source")
    print("Applied Arduino DNS core-lock patch")


def patch_selected_dependency(env):
    if "x4pro" not in env["PIOENV"] or env.get("ARDUINO_LIB_COMPILE_FLAG") == "Build":
        return
    patch_network_manager(env)
    selected = [builder for builder in env.GetLibBuilders()
                if builder.name == "AmneziaWG-ESP32" and builder.is_dependent]
    if len(selected) != 1:
        raise RuntimeError("Expected exactly one selected AmneziaWG-ESP32 dependency")

    project = Path(env["PROJECT_DIR"]).resolve()
    dependency = Path(selected[0].path).resolve()
    environment_root = (Path(env.subst("$PROJECT_LIBDEPS_DIR")) / env["PIOENV"]).resolve()
    if not is_within(dependency, environment_root):
        raise RuntimeError("WireGuard dependency is outside the selected environment")

    properties = dependency / "library.properties"
    if "version=0.1.0" not in properties.read_text().splitlines():
        raise RuntimeError("WireGuard patches require AmneziaWG-ESP32 0.1.0")

    states = []
    for relative, upstream, patched in TARGETS:
        target = (dependency / relative).resolve()
        if not is_within(target, dependency) or not target.is_file():
            raise RuntimeError("Missing or escaping WireGuard patch target: " + relative)
        current = digest(target)
        if current == upstream:
            states.append("upstream")
        elif current == patched:
            states.append("patched")
        else:
            raise RuntimeError("Unrecognized WireGuard source: " + relative)
    if len(set(states)) != 1:
        raise RuntimeError("WireGuard dependency is only partially patched")

    patch = project / "scripts" / PATCH
    process_env = {key: os.environ[key] for key in ("HOME", "PATH", "TMPDIR", "LANG") if key in os.environ}
    process_env.update(GIT_CEILING_DIRECTORIES=str(dependency.parent),
                       GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    command = ["git", "apply", "--check", "--unidiff-zero"]
    if states[0] == "patched":
        command.append("--reverse")
    result = subprocess.run(command + [str(patch)], cwd=dependency, env=process_env,
                            capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError("WireGuard patch does not apply:\n" + result.stderr)
    if states[0] == "patched":
        return

    subprocess.run(["git", "apply", "--unidiff-zero", str(patch)], cwd=dependency, env=process_env, check=True)
    for relative, _, expected in TARGETS:
        if digest(dependency / relative) != expected:
            raise RuntimeError("Unexpected patched WireGuard source: " + relative)
    print("Applied WireGuard lifecycle patch")


if "Import" in globals():
    Import("env")  # noqa: F821 -- supplied by SCons
    patch_selected_dependency(env)  # noqa: F821

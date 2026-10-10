#!/usr/bin/env python3
"""Isolation substrate (U2).

Runs the target side of a campaign as a confined, non-root container with no
internet egress, so a hostile target cannot reach the network or tamper with
host-side evidence. The harness core and the tamper-evident evidence stay on the
host; the target gets only a writable scratch mount and a Docker ``--internal``
network shared with the out-of-band sink and the co-located target.

Live container execution needs a reachable Docker daemon. The argv/policy builders
here are pure and unit-tested; the live boundary is validated by the generated
spec plus the manual smoke check in RUNBOOK.md. ``require_isolation`` fails closed
so a real target never runs unconfined by accident.
"""
from __future__ import annotations
import shutil
import subprocess
from dataclasses import dataclass

NOBODY = "65534:65534"  # non-root uid:gid (nobody:nogroup)


class IsolationUnavailable(RuntimeError):
    pass


def docker_available():
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


@dataclass(frozen=True)
class EgressPolicy:
    """Hosts the contained target may reach. The OOB sink is always allowed."""
    sink: tuple                 # (host, port)
    scope: tuple = ()           # additional (host, port) pairs in the declared scope

    def allowed(self):
        return (self.sink,) + tuple(self.scope)

    def check(self, host, port):
        return (host, port) in self.allowed()


@dataclass(frozen=True)
class SandboxSpec:
    image: str
    command: tuple
    scratch_dir: str            # host dir bind-mounted read-write at /work
    network: str                # name of the --internal docker network
    egress: EgressPolicy
    memory: str = "512m"
    pids: int = 256
    cpus: str = "1"
    user: str = NOBODY


def build_network_argv(name):
    # An --internal network has no route off itself: no internet egress. The sink
    # and the co-located target attach here and can reach each other, nothing else.
    return ["docker", "network", "create", "--internal", "--driver", "bridge", name]


def build_run_argv(spec):
    if spec.egress.sink is None:
        raise IsolationUnavailable("Egress policy must include the OOB sink")
    return ["docker", "run", "--rm", "--network", spec.network,
            "--user", spec.user, "--read-only", "--tmpfs", "/tmp",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", str(spec.pids), "--memory", spec.memory, "--cpus", spec.cpus,
            "-v", f"{spec.scratch_dir}:/work:rw", "-w", "/work",
            spec.image, *spec.command]


REQUIRED_FLAGS = ("--read-only", "--cap-drop", "no-new-privileges")


def validate_run_argv(argv):
    """Assert a run invocation carries the confinement invariants. Fail-closed."""
    if "--user" not in argv:
        raise IsolationUnavailable("target must run as a non-root user")
    user = argv[argv.index("--user") + 1]
    if not user or user.split(":")[0] in ("0", "root"):
        raise IsolationUnavailable("target must run as a non-root user")
    if "--network" not in argv or argv[argv.index("--network") + 1] in ("host", ""):
        raise IsolationUnavailable("target must attach to a non-host internal network")
    for flag in REQUIRED_FLAGS:
        if flag not in argv:
            raise IsolationUnavailable(f"missing confinement flag: {flag}")
    if "--privileged" in argv:
        raise IsolationUnavailable("privileged container denied")
    if any("docker.sock" in part for part in argv):
        raise IsolationUnavailable("docker socket mount denied")
    return True


def require_isolation():
    """Refuse to proceed with a real target when no isolation backend is usable."""
    if not docker_available():
        raise IsolationUnavailable(
            "No reachable Docker daemon; refusing to run a real target unconfined. "
            "Start Docker, or run the target in a separate VM/user per RUNBOOK.md.")
    return True

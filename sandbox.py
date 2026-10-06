#!/usr/bin/env python3
"""All-in-one sandbox chooser.

Pick a sandbox by answering a few requirements, or choose a type directly.
Sandboxes are created under ./sandboxes next to this script.

Types
  workspace  Clean folder with starter files. No package or process isolation.
  python     Workspace plus a virtual environment (isolated packages).
  jail       Throwaway filesystem jail via Linux namespaces + chroot.
  full       Workspace + virtualenv, with an option to run inside the jail.

This is a practical sandbox, not a security boundary against a determined
attacker. A jail hides the host filesystem from normal commands. It is not a
VM and does not stop kernel exploits.
"""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import subprocess
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SANDBOXES = ROOT / "sandboxes"
RUNTIME = Path("/tmp/sandbox-runtime")
TYPES = ("workspace", "python", "jail", "full")


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def valid_name(name: str) -> str:
    cleaned = name.strip().replace(" ", "-")
    if not cleaned or cleaned in {".", ".."} or "/" in cleaned or "\\" in cleaned:
        raise SystemExit(f"Invalid sandbox name: {name!r}")
    if not all(c.isalnum() or c in "-_." for c in cleaned):
        raise SystemExit("Name may only use letters, numbers, dot, dash, underscore.")
    return cleaned


def sandbox_dir(name: str) -> Path:
    return SANDBOXES / valid_name(name)


def runtime_dir(name: str) -> Path:
    return RUNTIME / valid_name(name)


def venv_dir(name: str) -> Path:
    # The user-visible folder is a FUSE share that rejects symlinks.
    # Python's venv always creates a lib64 symlink, so it lives in /tmp.
    return runtime_dir(name) / ".venv"


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def run(cmd: list[str], cwd: Path | None = None) -> None:
    print("+", " ".join(shlex.quote(c) for c in cmd))
    subprocess.run(cmd, cwd=cwd, check=True)


def ensure_base(name: str, kind: str) -> Path:
    path = sandbox_dir(name)
    if path.exists():
        raise SystemExit(f"Sandbox already exists: {path}")
    (path / "work").mkdir(parents=True)
    (path / "notes").mkdir()
    write(
        path / "SANDBOX.txt",
        textwrap.dedent(
            f"""\
            name: {name}
            type: {kind}
            created: {now()}
            path: {path}

            work/   your files
            notes/  scratch notes
            """
        ),
    )
    write(
        path / "work" / "hello.py",
        textwrap.dedent(
            """\
            print("hello from sandbox")
            print("this file lives only in this sandbox's work folder")
            """
        ),
    )
    return path


def create_workspace(name: str) -> Path:
    path = ensure_base(name, "workspace")
    write(
        path / "README.md",
        textwrap.dedent(
            f"""\
            # {name}

            Workspace sandbox. Files stay in this folder. Packages are not isolated
            unless you create a virtualenv later.

            Created {now()}.
            """
        ),
    )
    print(f"Workspace sandbox ready: {path}")
    return path


def create_python(name: str, kind: str = "python") -> Path:
    path = ensure_base(name, kind)
    venv = venv_dir(name)
    if venv.exists():
        shutil.rmtree(venv)
    venv.parent.mkdir(parents=True, exist_ok=True)
    run([sys.executable, "-m", "venv", str(venv)])
    pip = venv / "bin" / "pip"
    run([str(pip), "install", "--upgrade", "pip"])
    write(
        path / "README.md",
        textwrap.dedent(
            f"""\
            # {name}

            Python sandbox. Packages install only into a private virtualenv.

            The virtualenv lives at:
              {venv}

            It is not inside this folder because this file share cannot store
            the symlinks Python's venv creates.

            Run:
              {venv}/bin/python {path / "work" / "hello.py"}

            Or:
              python3 {ROOT / "sandbox.py"} run --name {name} -- python work/hello.py

            Created {now()}.
            """
        ),
    )
    write(path / "requirements.txt", "# add packages here, then run: python3 sandbox.py run --name {name} -- pip install -r requirements.txt\n")
    write(path / "venv.path", str(venv) + "\n")
    print(f"Python sandbox ready: {path}")
    print(f"Interpreter: {venv / 'bin' / 'python'}")
    return path


def jail_script(root: Path, net_off: bool) -> str:
    root_q = shlex.quote(str(root))
    net_note = "network namespace unshared (no host network)" if net_off else "network shared with host"
    return textwrap.dedent(
        f"""\
        set -uo pipefail
        root={root_q}
        mkdir -p "$root"/{{bin,lib,lib64,usr,etc,tmp,proc,dev,work,app}}
        mount --bind /bin "$root/bin"
        if [ -d /lib ]; then mount --bind /lib "$root/lib"; fi
        if [ -d /lib64 ]; then mount --bind /lib64 "$root/lib64" || true; fi
        mount --bind /usr "$root/usr"
        # Minimal /etc so DNS and passwd lookups work. Not a full host copy of secrets.
        if [ -f /etc/passwd ]; then cp /etc/passwd "$root/etc/passwd"; fi
        if [ -f /etc/group ]; then cp /etc/group "$root/etc/group"; fi
        if [ -f /etc/nsswitch.conf ]; then cp /etc/nsswitch.conf "$root/etc/nsswitch.conf"; fi
        if [ -f /etc/resolv.conf ]; then cp /etc/resolv.conf "$root/etc/resolv.conf"; fi
        mkdir -p "$root/etc/ssl" || true
        if [ -d /etc/ssl/certs ]; then cp -a /etc/ssl/certs "$root/etc/ssl/" || true; fi
        mount -t proc proc "$root/proc" || echo "warn: proc not mounted"
        mount -t tmpfs tmpfs "$root/tmp" || echo "warn: tmp not mounted"
        mount --bind /dev "$root/dev" 2>/dev/null || echo "warn: dev not mounted"
        echo "jail root=$root ({net_note})"
        chroot "$root" /bin/bash -lc "$SANDBOX_CMD"
        """
    )


def run_jail(name: str, command: str, net_off: bool = False) -> int:
    path = sandbox_dir(name)
    if not path.is_dir():
        raise SystemExit(f"No sandbox named {name!r}. Create one first.")
    root = runtime_dir(name) / "jail-root"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    # Copy the user's work tree into the jail so the command can see it, not the host.
    work_src = path / "work"
    work_dst = root / "work"
    work_dst.mkdir(parents=True, exist_ok=True)
    if work_src.is_dir():
        shutil.copytree(work_src, work_dst, dirs_exist_ok=True)
    flags = ["unshare", "--mount", "--pid", "--fork", "--uts"]
    if net_off:
        flags.append("--net")
    flags += ["bash", "-c", jail_script(root, net_off)]
    print(f"Entering jail for {name!r}: {command}")
    env = os.environ.copy()
    env["SANDBOX_CMD"] = command
    completed = subprocess.run(flags, env=env)
    return completed.returncode


def create_jail(name: str) -> Path:
    path = ensure_base(name, "jail")
    write(
        path / "README.md",
        textwrap.dedent(
            f"""\
            # {name}

            Filesystem jail sandbox. Run commands with:

              python3 {ROOT / "sandbox.py"} run --name {name} --jail -- ls -la /work

            The jailed command sees /work (a copy of this sandbox's work/) and a
            minimal system. It does not see the host home or this tool's other files.
            Add --net-off to also drop network.

            Created {now()}.
            """
        ),
    )
    print(f"Jail sandbox ready: {path}")
    return path


def create_full(name: str) -> Path:
    path = create_python(name, kind="full")
    # create_python already wrote README; extend it.
    readme = path / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8")
        + textwrap.dedent(
            f"""\

            This is a full sandbox: isolated packages AND an optional filesystem jail.

              {venv_dir(name) / "bin" / "python"} {path / "work" / "hello.py"}
              python3 {ROOT / "sandbox.py"} run --name {name} --jail -- python3 /work/hello.py
            """
        ),
        encoding="utf-8",
    )
    print(f"Full sandbox ready: {path}")
    return path


def create(kind: str, name: str) -> Path:
    SANDBOXES.mkdir(parents=True, exist_ok=True)
    if kind == "workspace":
        return create_workspace(name)
    if kind == "python":
        return create_python(name)
    if kind == "jail":
        return create_jail(name)
    if kind == "full":
        return create_full(name)
    raise SystemExit(f"Unknown type {kind!r}. Choose from: {', '.join(TYPES)}")


def list_sandboxes() -> None:
    if not SANDBOXES.is_dir() or not any(SANDBOXES.iterdir()):
        print("No sandboxes yet.")
        return
    print(f"{'NAME':<20} {'TYPE':<12} PATH")
    for path in sorted(p for p in SANDBOXES.iterdir() if p.is_dir()):
        kind = "?"
        meta = path / "SANDBOX.txt"
        if meta.is_file():
            for line in meta.read_text(encoding="utf-8").splitlines():
                if line.startswith("type:"):
                    kind = line.split(":", 1)[1].strip()
        print(f"{path.name:<20} {kind:<12} {path}")


def remove(name: str) -> None:
    path = sandbox_dir(name)
    runtime = runtime_dir(name)
    if not path.is_dir() and not runtime.is_dir():
        raise SystemExit(f"No sandbox named {name!r}.")
    if path.is_dir():
        shutil.rmtree(path)
        print(f"Removed {path}")
    if runtime.is_dir():
        shutil.rmtree(runtime)
        print(f"Removed runtime {runtime}")


def run_in(name: str, command: str, jail: bool, net_off: bool) -> int:
    path = sandbox_dir(name)
    if not path.is_dir():
        raise SystemExit(f"No sandbox named {name!r}.")
    if jail:
        return run_jail(name, command, net_off=net_off)
    env = os.environ.copy()
    venv_bin = venv_dir(name) / "bin"
    if venv_bin.is_dir():
        env["VIRTUAL_ENV"] = str(venv_dir(name))
        env["PATH"] = str(venv_bin) + os.pathsep + env.get("PATH", "")
    print(f"Running in {path}: {command}")
    completed = subprocess.run(["bash", "-lc", command], cwd=path, env=env)
    return completed.returncode


def recommend(packages: bool, untrusted: bool, network: bool) -> str:
    if untrusted and packages:
        return "full"
    if untrusted:
        return "jail"
    if packages:
        return "python"
    return "workspace"


def explain(kind: str) -> str:
    return {
        "workspace": "Clean folder only. Fastest. No package or process isolation.",
        "python": "Folder + virtualenv. Packages cannot clash with the system install.",
        "jail": "Filesystem jail. Commands see a minimal root and /work, not the host tree.",
        "full": "Virtualenv plus the jail option. Use this for untrusted code that needs packages.",
    }[kind]


def guided() -> None:
    print("Answer a few questions. The tool picks a sandbox type. You can override it.\n")
    packages = ask_yn("Will this sandbox install Python packages?")
    untrusted = ask_yn("Is the code untrusted, or should it be blocked from host files?")
    network = ask_yn("Should the jailed run be cut off from the network? (only matters for jail/full)")
    kind = recommend(packages, untrusted, network)
    print(f"\nSuggested: {kind}")
    print(explain(kind))
    print("\nAll types:")
    for item in TYPES:
        mark = " <-- suggested" if item == kind else ""
        print(f"  {item:<10} {explain(item)}{mark}")
    chosen = input(f"\nType to create [{kind}]: ").strip() or kind
    if chosen not in TYPES:
        raise SystemExit(f"Unknown type {chosen!r}.")
    name = input("Sandbox name: ").strip()
    if not name:
        raise SystemExit("Name is required.")
    create(chosen, name)
    if chosen in {"jail", "full"} and ask_yn("Run a quick jail check now (python3 /work/hello.py)?"):
        code = run_jail(valid_name(name), "python3 /work/hello.py", net_off=network and chosen in {"jail", "full"})
        raise SystemExit(code)


def ask_yn(prompt: str) -> bool:
    answer = input(f"{prompt} [y/N]: ").strip().lower()
    return answer in {"y", "yes"}


def menu() -> None:
    print(
        textwrap.dedent(
            """\
            Sandbox chooser
              1  Guided — answer requirements, then pick or accept the suggestion
              2  Workspace sandbox
              3  Python package sandbox
              4  Filesystem jail sandbox
              5  Full sandbox (packages + jail)
              6  List sandboxes
              7  Run a command in a sandbox
              8  Remove a sandbox
              0  Quit
            """
        )
    )
    choice = input("Choose: ").strip()
    if choice in {"0", "q", ""}:
        return
    if choice == "1":
        guided()
        return
    if choice in {"2", "3", "4", "5"}:
        kind = {"2": "workspace", "3": "python", "4": "jail", "5": "full"}[choice]
        print(explain(kind))
        name = input("Sandbox name: ").strip()
        create(kind, name)
        return
    if choice == "6":
        list_sandboxes()
        return
    if choice == "7":
        list_sandboxes()
        name = input("Sandbox name: ").strip()
        jail = ask_yn("Run inside the filesystem jail?")
        net_off = ask_yn("Cut off network?") if jail else False
        command = input("Command: ").strip() or "ls -la"
        raise SystemExit(run_in(name, command, jail, net_off))
    if choice == "8":
        list_sandboxes()
        name = input("Sandbox name to remove: ").strip()
        if ask_yn(f"Delete {name}?"):
            remove(name)
        return
    raise SystemExit("Unknown choice.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create and use a sandbox by type or by requirements.")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("menu", help="interactive menu")
    sub.add_parser("guide", help="choose from requirements")
    sub.add_parser("list", help="list sandboxes")

    create_p = sub.add_parser("create", help="create a sandbox")
    create_p.add_argument("--type", required=True, choices=TYPES)
    create_p.add_argument("--name", required=True)

    run_p = sub.add_parser("run", help="run a command in a sandbox")
    run_p.add_argument("--name", required=True)
    run_p.add_argument("--jail", action="store_true")
    run_p.add_argument("--net-off", action="store_true")
    run_p.add_argument("command", nargs=argparse.REMAINDER)

    rm_p = sub.add_parser("remove", help="delete a sandbox")
    rm_p.add_argument("--name", required=True)
    return parser


def main(argv: list[str]) -> int:
    if not argv:
        menu()
        return 0
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd in {None, "menu"}:
        menu()
        return 0
    if args.cmd == "guide":
        guided()
        return 0
    if args.cmd == "list":
        list_sandboxes()
        return 0
    if args.cmd == "create":
        create(args.type, args.name)
        return 0
    if args.cmd == "remove":
        remove(args.name)
        return 0
    if args.cmd == "run":
        command_parts = args.command
        if command_parts and command_parts[0] == "--":
            command_parts = command_parts[1:]
        command = shlex.join(command_parts) if command_parts else "ls -la"
        return run_in(args.name, command, args.jail, args.net_off)
    parser.print_help()
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except subprocess.CalledProcessError as exc:
        print(f"Command failed with exit code {exc.returncode}", file=sys.stderr)
        raise SystemExit(exc.returncode)

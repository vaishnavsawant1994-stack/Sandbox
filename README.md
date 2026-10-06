# Sandbox chooser

One tool. Pick the isolation you need, or answer three questions and accept the suggestion.

```bash
python3 sandbox.py
```

## Choose by requirement

| Need | Type to pick |
| --- | --- |
| A clean folder only | `workspace` |
| Python packages that must not touch the system | `python` |
| Commands that must not see host files | `jail` |
| Packages and a filesystem jail | `full` |

Guided mode asks those questions and suggests a type. You can still override it.

## Commands

```bash
python3 sandbox.py guide
python3 sandbox.py create --type python --name demo
python3 sandbox.py create --type full --name trial
python3 sandbox.py list
python3 sandbox.py run --name demo -- python work/hello.py
python3 sandbox.py run --name trial --jail -- python3 /work/hello.py
python3 sandbox.py run --name trial --jail --net-off -- python3 /work/hello.py
python3 sandbox.py remove --name demo
```

Sandboxes are created in `sandboxes/` next to this script. Python virtualenvs and jail roots live in `/tmp/sandbox-runtime/` because this file share cannot store symlinks, and Python's venv needs one.

## What each type actually isolates

- `workspace` isolates nothing except by convention: files live in that folder.
- `python` isolates installed packages in `.venv`. It does not hide host files.
- `jail` starts a new mount and PID namespace, then chroots into a minimal root. The command sees `/work` (a copy of that sandbox's `work/`) plus `/bin`, `/lib`, and `/usr`. It does not see the rest of the host tree. `--net-off` also drops the network.
- `full` is a virtualenv plus the jail option.

This is a practical sandbox for experiments. It is not a virtual machine and not a defense against kernel exploits.

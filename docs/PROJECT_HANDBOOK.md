# Sandbox Chooser CLI — Project Handbook

> Owner: `vaishnavsawant1994-stack` · Repository: `Sandbox` · Reviewed: 15 November 2026  
> Documentation maturity: repo/source/manifest inspection; **not** an independent live release certification.

## Project overview and audience
Small Python utility for selecting and creating development workspace isolation modes, from an ordinary folder to a Linux namespace jail.

**Intended users:** Developers who need disposable test environments.

## Main features / user journeys
1. Guided selection of workspace/python/jail/full modes.
2. Create and list named sandbox workspaces.
3. Run commands inside selected isolation level.
4. Document actual isolation properties and limitations.

These items are code areas and project goals; individual end-to-end flows must be qualified separately.

## Architecture, stack and repository layout
Single Python CLI in `sandbox.py` plus README and gitignore. Workspace and virtualenv modes isolate files/packages, not hostile process execution; jail/full modes use Linux namespace/chroot features where supported.

## What is actually qualified or still outstanding
CLI source and usage documentation are present. Do not describe this as a VM, hardened container or boundary against determined attackers.

Source code and historical QA reports are distinct from passing current CI, real integrations, live deployment and production acceptance.

## Installation and developer operations
`python3 sandbox.py guide`, `python3 sandbox.py create --type python --name demo`, `python3 sandbox.py list`, `python3 sandbox.py run --name demo -- python work/hello.py`. Jail modes require compatible Linux permissions/features.

Before running migrations, scripts or providers, verify environment, branches, private credentials, target database and rollback. Do not use actual user/customer records in unqualified development.

## Security and quality requirements
- A Python virtual environment is not a security sandbox.
- Linux user/mount namespaces do not prevent kernel vulnerabilities.
- Never run unknown malware or hostile code assuming containment.
Release acceptance also requires role/session auditing, dependency/security review, accessible interaction, observability, backups, restore and a controlled rollback where applicable.

## Prioritized roadmap
1. Add platform compatibility matrix and automated smoke tests.
2. Implement clear failure messages for missing namespace capabilities.
3. Define cleanup/retention behavior.
4. Document threat model and non-goals.

## Source-of-truth documents
- [`README.md`](../README.md)
- [`sandbox.py`](../sandbox.py)

**Maintenance:** Revisit this guide when functional implementation, project boundaries or deployment gates change. For precise status, read qualified exact-commit test and release artifacts.

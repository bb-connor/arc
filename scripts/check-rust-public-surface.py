#!/usr/bin/env python3

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
import sys
import tomllib


def duplicate_values(values: list[str]) -> list[str]:
    counts = Counter(values)
    return sorted(value for value, count in counts.items() if count > 1)


def read_metadata_list(metadata: dict[str, object], key: str) -> list[str]:
    values = metadata.get(key, [])
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise TypeError(f"workspace.metadata.chio.{key} must be a list of strings")
    return values


def require_sorted_unique(key: str, values: list[str], errors: list[str]) -> None:
    duplicates = duplicate_values(values)
    if duplicates:
        errors.append(f"duplicate {key} entries: {', '.join(duplicates)}")
    if values != sorted(values):
        errors.append(f"{key} must be sorted lexicographically")


def require_readme(
    manifest_path: Path,
    display_path: Path,
    package: dict[str, object],
    label: str,
    errors: list[str],
) -> None:
    readme = package.get("readme")
    if not readme:
        errors.append(f"{display_path} is {label} but does not declare a crate README.")
        return
    if not isinstance(readme, str):
        errors.append(f"{display_path} declares non-string README metadata.")
        return

    readme_path = manifest_path.parent / readme
    if not readme_path.exists():
        errors.append(f"{display_path} points to missing README {readme!r}.")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--workspace-manifest",
        default=Path(__file__).resolve().parents[1] / "Cargo.toml",
        type=Path,
        help="Path to the workspace Cargo.toml to validate.",
    )
    args = parser.parse_args()

    workspace_manifest = args.workspace_manifest.resolve()
    root = workspace_manifest.parent
    workspace = tomllib.loads(workspace_manifest.read_text())
    members = workspace["workspace"]["members"]
    metadata = workspace["workspace"]["metadata"]["chio"]
    entrypoints = read_metadata_list(metadata, "rust_public_entrypoints")
    registry_crates = read_metadata_list(metadata, "rust_registry_public_crates")

    entrypoint_names = set(entrypoints)
    registry_names = set(registry_crates)

    errors: list[str] = []
    require_sorted_unique("rust_public_entrypoints", entrypoints, errors)
    require_sorted_unique("rust_registry_public_crates", registry_crates, errors)

    seen_names: set[str] = set()

    for member in members:
        manifest_path = root / member / "Cargo.toml"
        manifest = tomllib.loads(manifest_path.read_text())
        package = manifest["package"]
        crate_name = package["name"]
        seen_names.add(crate_name)
        display_path = manifest_path.relative_to(root)

        if crate_name in registry_names:
            if package.get("publish") is False:
                errors.append(
                    f"{display_path} is listed in "
                    "workspace.metadata.chio.rust_registry_public_crates "
                    "but sets publish = false."
                )
            require_readme(
                manifest_path,
                display_path,
                package,
                "a registry-public crate",
                errors,
            )
        elif package.get("publish") is not False:
            errors.append(
                f"{display_path} must set publish = false or be listed in "
                "workspace.metadata.chio.rust_registry_public_crates."
            )

        if crate_name in entrypoint_names:
            require_readme(
                manifest_path,
                display_path,
                package,
                "a public entrypoint",
                errors,
            )

    missing_entrypoints = sorted(entrypoint_names - seen_names)
    if missing_entrypoints:
        errors.append(
            "workspace.metadata.chio.rust_public_entrypoints references unknown "
            f"crates: {', '.join(missing_entrypoints)}"
        )

    missing_registry_crates = sorted(registry_names - seen_names)
    if missing_registry_crates:
        errors.append(
            "workspace.metadata.chio.rust_registry_public_crates references unknown "
            f"crates: {', '.join(missing_registry_crates)}"
        )

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print(
        "Rust public surface policy is consistent: every workspace member is "
        "either publish=false or explicitly registry-public, and every public "
        "entrypoint has a README."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

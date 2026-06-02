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


def require_description(
    display_path: Path,
    package: dict[str, object],
    label: str,
    errors: list[str],
) -> None:
    description = package.get("description")
    if not isinstance(description, str) or not description.strip():
        errors.append(
            f"{display_path} is {label} but does not declare a non-empty "
            "package description."
        )


def existing_auto_bin_sources(manifest_path: Path) -> list[Path]:
    src_dir = manifest_path.parent / "src"
    sources: list[Path] = []
    main_rs = src_dir / "main.rs"
    if main_rs.is_file():
        sources.append(main_rs)

    bin_dir = src_dir / "bin"
    if not bin_dir.exists():
        return sources

    sources.extend(path for path in sorted(bin_dir.glob("*.rs")) if path.is_file())
    sources.extend(
        path / "main.rs"
        for path in sorted(bin_dir.iterdir())
        if path.is_dir() and (path / "main.rs").exists()
    )
    return sources


def target_path(manifest_path: Path, target: dict[str, object], default: str) -> Path:
    path = target.get("path")
    if isinstance(path, str):
        return manifest_path.parent / path
    return manifest_path.parent / default


def require_implementation_target(
    manifest_path: Path,
    display_path: Path,
    manifest: dict[str, object],
    package: dict[str, object],
    label: str,
    errors: list[str],
) -> None:
    checked_sources: list[Path] = []

    lib = manifest.get("lib")
    if isinstance(lib, dict):
        source = target_path(manifest_path, lib, "src/lib.rs")
        if not source.is_file():
            errors.append(
                f"{display_path} declares a lib target at "
                f"{source.relative_to(manifest_path.parent)} but the file is missing."
            )
        checked_sources.append(source)
    elif package.get("autolib") is not False:
        source = manifest_path.parent / "src/lib.rs"
        if source.is_file():
            checked_sources.append(source)

    bins = manifest.get("bin", [])
    if isinstance(bins, list):
        for bin_target in bins:
            if not isinstance(bin_target, dict):
                continue
            source = target_path(manifest_path, bin_target, "src/main.rs")
            if not source.is_file():
                errors.append(
                    f"{display_path} declares a bin target at "
                    f"{source.relative_to(manifest_path.parent)} but the file is missing."
                )
            checked_sources.append(source)
    elif bins:
        errors.append(f"{display_path} declares malformed bin target metadata.")

    if package.get("autobins") is not False:
        checked_sources.extend(existing_auto_bin_sources(manifest_path))

    if not any(source.is_file() for source in checked_sources):
        errors.append(
            f"{display_path} is {label} but does not declare an existing lib "
            "or bin target."
        )


def package_chio_metadata(
    display_path: Path,
    package: dict[str, object],
    errors: list[str],
) -> dict[str, object]:
    metadata = package.get("metadata", {})
    if not isinstance(metadata, dict):
        errors.append(f"{display_path} declares non-table package.metadata.")
        return {}

    chio_metadata = metadata.get("chio", {})
    if not isinstance(chio_metadata, dict):
        errors.append(f"{display_path} declares non-table package.metadata.chio.")
        return {}

    return chio_metadata


def non_dev_dependency_entries(
    manifest: dict[str, object],
) -> list[tuple[str, str, object]]:
    entries: list[tuple[str, str, object]] = []
    for table_name in ("dependencies", "build-dependencies"):
        table = manifest.get(table_name, {})
        if isinstance(table, dict):
            entries.extend((table_name, name, value) for name, value in table.items())

    targets = manifest.get("target", {})
    if isinstance(targets, dict):
        for target_name, target in targets.items():
            if not isinstance(target, dict):
                continue
            for table_name in ("dependencies", "build-dependencies"):
                table = target.get(table_name, {})
                if isinstance(table, dict):
                    entries.extend(
                        (
                            f"target.{target_name}.{table_name}",
                            name,
                            value,
                        )
                        for name, value in table.items()
                    )

    return entries


def dependency_path(
    root: Path,
    manifest_path: Path,
    workspace_dependencies: dict[str, object],
    dependency_name: str,
    dependency: object,
) -> Path | None:
    dependency_base = manifest_path.parent
    dependency_spec = dependency
    if isinstance(dependency_spec, str):
        return None
    if not isinstance(dependency_spec, dict):
        return None
    if dependency_spec.get("workspace") is True:
        dependency_spec = workspace_dependencies.get(dependency_name)
        dependency_base = root
        if isinstance(dependency_spec, str) or not isinstance(dependency_spec, dict):
            return None

    path = dependency_spec.get("path")
    if not isinstance(path, str):
        return None
    return (dependency_base / path).resolve()


def require_registry_dependency_closure(
    root: Path,
    manifest_path: Path,
    display_path: Path,
    manifest: dict[str, object],
    workspace_dependencies: dict[str, object],
    registry_names: set[str],
    member_names_by_dir: dict[Path, str],
    errors: list[str],
) -> None:
    for _table_name, dependency_name, dependency in non_dev_dependency_entries(manifest):
        resolved_dependency_path = dependency_path(
            root,
            manifest_path,
            workspace_dependencies,
            dependency_name,
            dependency,
        )
        if resolved_dependency_path is None:
            continue

        dependency_crate = member_names_by_dir.get(resolved_dependency_path)
        if dependency_crate is None or dependency_crate in registry_names:
            continue

        errors.append(
            f"{display_path} is registry-public but dependency "
            f"`{dependency_name}` points at workspace crate `{dependency_crate}`, "
            "which is not listed in "
            "workspace.metadata.chio.rust_registry_public_crates."
        )


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
    workspace_dependencies = workspace["workspace"].get("dependencies", {})
    if not isinstance(workspace_dependencies, dict):
        workspace_dependencies = {}
    entrypoints = read_metadata_list(metadata, "rust_public_entrypoints")
    registry_crates = read_metadata_list(metadata, "rust_registry_public_crates")

    entrypoint_names = set(entrypoints)
    registry_names = set(registry_crates)

    errors: list[str] = []
    require_sorted_unique("rust_public_entrypoints", entrypoints, errors)
    require_sorted_unique("rust_registry_public_crates", registry_crates, errors)

    seen_names: set[str] = set()
    member_records: list[tuple[str, Path, Path, dict[str, object], dict[str, object]]] = []
    member_names_by_dir: dict[Path, str] = {}

    for member in members:
        manifest_path = root / member / "Cargo.toml"
        manifest = tomllib.loads(manifest_path.read_text())
        package = manifest["package"]
        crate_name = package["name"]
        seen_names.add(crate_name)
        display_path = manifest_path.relative_to(root)
        member_records.append((crate_name, manifest_path, display_path, manifest, package))
        member_names_by_dir[manifest_path.parent.resolve()] = crate_name

    for crate_name, manifest_path, display_path, manifest, package in member_records:
        chio_metadata = package_chio_metadata(display_path, package, errors)
        local_public_entrypoint = chio_metadata.get("public_entrypoint", False)
        if not isinstance(local_public_entrypoint, bool):
            errors.append(
                f"{display_path} declares non-boolean "
                "package.metadata.chio.public_entrypoint."
            )
            local_public_entrypoint = False

        if local_public_entrypoint and crate_name not in entrypoint_names:
            errors.append(
                f"{display_path} declares package.metadata.chio.public_entrypoint "
                "= true but is missing from "
                "workspace.metadata.chio.rust_public_entrypoints."
            )

        if crate_name in registry_names:
            if package.get("publish") is False:
                errors.append(
                    f"{display_path} is listed in "
                    "workspace.metadata.chio.rust_registry_public_crates "
                    "but sets publish = false."
                )
            require_description(
                display_path,
                package,
                "a registry-public crate",
                errors,
            )
            require_readme(
                manifest_path,
                display_path,
                package,
                "a registry-public crate",
                errors,
            )
            require_implementation_target(
                manifest_path,
                display_path,
                manifest,
                package,
                "a registry-public crate",
                errors,
            )
            require_registry_dependency_closure(
                root,
                manifest_path,
                display_path,
                manifest,
                workspace_dependencies,
                registry_names,
                member_names_by_dir,
                errors,
            )
        elif package.get("publish") is not False:
            errors.append(
                f"{display_path} must set publish = false or be listed in "
                "workspace.metadata.chio.rust_registry_public_crates."
            )

        if crate_name in entrypoint_names:
            require_description(
                display_path,
                package,
                "a public entrypoint",
                errors,
            )
            require_implementation_target(
                manifest_path,
                display_path,
                manifest,
                package,
                "a public entrypoint",
                errors,
            )
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
        "Rust surface has a README, description, and implementation target."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path
import sys
import tomllib


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    workspace = tomllib.loads((root / "Cargo.toml").read_text())
    members = workspace["workspace"]["members"]
    entrypoints = set(
        workspace["workspace"]["metadata"]["arc"]["rust_public_entrypoints"]
    )

    errors: list[str] = []
    seen_names: set[str] = set()

    for member in members:
        manifest_path = root / member / "Cargo.toml"
        manifest = tomllib.loads(manifest_path.read_text())
        package = manifest["package"]
        crate_name = package["name"]
        seen_names.add(crate_name)

        if package.get("publish") is not False:
            errors.append(
                f"{manifest_path.relative_to(root)} must set publish = false "
                f"until the Rust registry surface is intentionally opened."
            )

        if crate_name in entrypoints:
            readme = package.get("readme")
            if not readme:
                errors.append(
                    f"{manifest_path.relative_to(root)} is a public entrypoint "
                    f"but does not declare a crate README."
                )
                continue

            readme_path = manifest_path.parent / readme
            if not readme_path.exists():
                errors.append(
                    f"{manifest_path.relative_to(root)} points to missing README "
                    f"{readme!r}."
                )

    missing = sorted(entrypoints - seen_names)
    if missing:
        errors.append(
            "workspace.metadata.arc.rust_public_entrypoints references unknown "
            f"crates: {', '.join(missing)}"
        )

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print(
        "Rust public surface policy is consistent: all workspace members are "
        "publish=false and every public entrypoint has a README."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

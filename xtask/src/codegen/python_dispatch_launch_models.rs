//! Preserve the required nullable fields of dispatch launch evidence.

use std::{fs, path::Path};

use crate::{display_path, XtaskError};

pub(super) fn harden(root: &Path) -> Result<(), XtaskError> {
    for (file, class, security_base) in [
        (
            "kernel/caller_dispatch_authorization_schema.py",
            "CallerDispatchLaunch",
            true,
        ),
        (
            "receipt/admission_metadata_schema.py",
            "DispatchLaunch",
            false,
        ),
    ] {
        let path = root.join(file);
        let source = fs::read_to_string(&path)
            .map_err(|error| XtaskError::Io(display_path(&path), error))?;
        let rewritten = harden_source(&source, class, security_base).map_err(|error| {
            XtaskError::ToolFailed(format!("Python dispatch launch model {file}: {error}"))
        })?;
        fs::write(&path, rewritten).map_err(|error| XtaskError::Io(display_path(&path), error))?;
    }
    Ok(())
}

const FIELDS: &str = "    model_config = ConfigDict(\n        extra=\"forbid\",\n    )\n    native_launch: NativeLaunch | None = None\n    worker_profile: WorkerProfile | None = None\n";
const REQUIRED_FIELDS: &str = "    model_config = ConfigDict(\n        extra=\"forbid\",\n    )\n    native_launch: NativeLaunch | None = Field(...)\n    worker_profile: WorkerProfile | None = Field(...)\n";
const SECURITY_IMPORT: &str =
    "from chio_sdk._manifest_wire import SecurityWireModel as BaseModel\n";
const STRICT_ATTEMPT: &str = "    launch_attempt: conint(strict=True, ge=1, le=4294967295)\n";
const COERCING_ATTEMPT: &str = "    launch_attempt: conint(ge=1, le=4294967295)\n";

fn harden_source(source: &str, class: &str, security_base: bool) -> Result<String, &'static str> {
    let generated = format!("class {class}(BaseModel):\n{FIELDS}\n\n");
    if source.matches(&generated).count() != 1 {
        return Err("generated dispatch launch object inventory changed");
    }
    let expected_attempt = if security_base {
        STRICT_ATTEMPT
    } else {
        COERCING_ATTEMPT
    };
    if source.matches(expected_attempt).count() != 1 {
        return Err("generated worker attempt inventory changed");
    }
    let base = if security_base {
        "DispatchLaunchBaseModel"
    } else {
        "BaseModel"
    };
    let mut rewritten = source.replacen(
        &generated,
        &format!("class {class}({base}):\n{REQUIRED_FIELDS}\n\n"),
        1,
    );
    if security_base {
        if source.matches(SECURITY_IMPORT).count() != 1
            || source.contains("DispatchLaunchBaseModel")
        {
            return Err("generated dispatch launch security base changed");
        }
        rewritten = rewritten.replacen(
            SECURITY_IMPORT,
            &format!(
                "{SECURITY_IMPORT}from pydantic import BaseModel as DispatchLaunchBaseModel\n"
            ),
            1,
        );
    } else {
        rewritten = rewritten.replacen(COERCING_ATTEMPT, STRICT_ATTEMPT, 1);
    }
    Ok(rewritten)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(class: &str, security_base: bool) -> String {
        let (import, attempt) = if security_base {
            (SECURITY_IMPORT, STRICT_ATTEMPT)
        } else {
            ("from pydantic import BaseModel\n", COERCING_ATTEMPT)
        };
        format!(
            "{import}class WorkerProfile(BaseModel):\n{attempt}\nclass {class}(BaseModel):\n{FIELDS}\n\nclass Other(BaseModel):\n    nullable: str | None = None\n"
        )
    }

    #[test]
    fn changed_receipt_worker_attempt_generation_is_refused() {
        let source = fixture("DispatchLaunch", false).replace(COERCING_ATTEMPT, STRICT_ATTEMPT);
        assert_eq!(
            harden_source(&source, "DispatchLaunch", false),
            Err("generated worker attempt inventory changed")
        );
    }

    #[test]
    fn changed_dispatch_launch_generation_is_refused() {
        let source = fixture("CallerDispatchLaunch", true);
        for (changed, expected) in [
            (
                source.replace("CallerDispatchLaunch", "OtherLaunch"),
                "generated dispatch launch object inventory changed",
            ),
            (
                source.replace("worker_profile: WorkerProfile", "worker_profile: object"),
                "generated dispatch launch object inventory changed",
            ),
            (
                source.replace(
                    "    worker_profile: WorkerProfile | None = None\n",
                    "    worker_profile: WorkerProfile | None = None\n    extra_field: str | None = None\n",
                ),
                "generated dispatch launch object inventory changed",
            ),
            (
                source.replace(STRICT_ATTEMPT, COERCING_ATTEMPT),
                "generated worker attempt inventory changed",
            ),
            (
                source.replace(SECURITY_IMPORT, "from pydantic import BaseModel\n"),
                "generated dispatch launch security base changed",
            ),
            (
                format!("{source}{source}"),
                "generated dispatch launch object inventory changed",
            ),
        ] {
            assert_eq!(
                harden_source(&changed, "CallerDispatchLaunch", true),
                Err(expected)
            );
        }
    }
}

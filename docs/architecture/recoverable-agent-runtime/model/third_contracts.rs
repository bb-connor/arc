//! Symbolic authorization contracts, not signature or label-algebra verification.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageFault {
    None,
    AnyOwnerSuffices,
    IgnoreApprovalContext,
    CountSignatureAliases,
}

fn accepts(required: u8, covered: u8, binding: u8, fault: CoverageFault) -> bool {
    // Four independent bits: action, requirements/target, challenge, source context.
    let context_matches = binding == 0b1111 || fault == CoverageFault::IgnoreApprovalContext;
    // Four obligation bits: owner A, owner B, compartment, integrity endorsement.
    let obligations = if fault == CoverageFault::AnyOwnerSuffices {
        required & covered != 0
    } else {
        required & covered == required
    };
    context_matches && obligations
}

pub fn coverage(fault: CoverageFault) -> Result<usize, &'static str> {
    let mut cases = 0;
    for required in 1..16u8 {
        for covered in 0..16u8 {
            for binding in 0..16u8 {
                cases += 1;
                let result = accepts(required, covered, binding, fault);
                if result && binding != 15 {
                    return Err("approval from another action target challenge or source satisfied coverage");
                }
                for obligation in 0..4 {
                    let bit = 1 << obligation;
                    if result && required & bit != 0 && covered & bit == 0 {
                        return Err(
                            "partial owner or power coverage authorized the complete release",
                        );
                    }
                }
                if binding == 15 && required & covered == required && !result {
                    return Err("complete exact coverage was incorrectly refused");
                }
            }
        }
    }
    // Two threshold signatures may be two keys or delegation aliases of one principal.
    for first_principal in 0..2 {
        for second_principal in 0..2 {
            cases += 1;
            let counted = if fault == CoverageFault::CountSignatureAliases
                || first_principal != second_principal
            {
                2
            } else {
                1
            };
            if counted >= 2 && first_principal == second_principal {
                return Err("two aliases of one principal satisfied a two-principal obligation");
            }
            if first_principal != second_principal && counted != 2 {
                return Err("two distinct authorized principals were incorrectly refused");
            }
        }
    }
    Ok(cases)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FabricEnsureMode {
    ActiveReleaseOnly,
    AllowPayloadPromotion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FabricReleasePlan {
    RestoreActive,
    PromoteSupervisorPayload,
}

pub fn plan_fabric_release(
    mode: FabricEnsureMode,
    has_active_release: bool,
    active_matches_payload: bool,
) -> Result<FabricReleasePlan, String> {
    match mode {
        FabricEnsureMode::ActiveReleaseOnly => {
            if !has_active_release {
                return Err("FABRIC_ACTIVE_RELEASE_REQUIRED".to_string());
            }
            let _ = active_matches_payload;
            Ok(FabricReleasePlan::RestoreActive)
        }
        FabricEnsureMode::AllowPayloadPromotion => {
            if has_active_release && active_matches_payload {
                Ok(FabricReleasePlan::RestoreActive)
            } else {
                Ok(FabricReleasePlan::PromoteSupervisorPayload)
            }
        }
    }
}

pub fn clamp_runtime_reconcile_parallelism(value: u64) -> usize {
    value.clamp(1, 16) as usize
}

#[cfg(test)]
mod tests {
    use super::{
        plan_fabric_release, FabricEnsureMode, FabricReleasePlan,
    };

    #[test]
    fn recovery_no_adopta_payload_nuevo() {
        assert_eq!(
            plan_fabric_release(FabricEnsureMode::ActiveReleaseOnly, true, false).unwrap(),
            FabricReleasePlan::RestoreActive
        );
    }

    #[test]
    fn recovery_sin_active_falla_explicito() {
        let error = plan_fabric_release(FabricEnsureMode::ActiveReleaseOnly, false, false)
            .expect_err("sin activeRelease");
        assert_eq!(error, "FABRIC_ACTIVE_RELEASE_REQUIRED");
    }

    #[test]
    fn update_explicito_puede_promover_payload() {
        assert_eq!(
            plan_fabric_release(FabricEnsureMode::AllowPayloadPromotion, true, false).unwrap(),
            FabricReleasePlan::PromoteSupervisorPayload
        );
    }

    #[test]
    fn update_no_repromueve_si_ya_coincide() {
        assert_eq!(
            plan_fabric_release(FabricEnsureMode::AllowPayloadPromotion, true, true).unwrap(),
            FabricReleasePlan::RestoreActive
        );
    }

    #[test]
    fn commissioning_sin_fabric_promueve_payload() {
        assert_eq!(
            plan_fabric_release(FabricEnsureMode::AllowPayloadPromotion, false, false).unwrap(),
            FabricReleasePlan::PromoteSupervisorPayload
        );
    }
}

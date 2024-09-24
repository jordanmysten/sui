use std::collections::BTreeSet;
use move_binary_format::compatibility::{Compatibility, CompatibilityMode};
use move_binary_format::normalized::{Enum, Function, Struct};
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::IdentStr;
use thiserror::Error;
use anyhow::{anyhow};
use move_core_types::language_storage::ModuleId;

#[derive(Debug, Error)]
enum UpgradeCompatibilityModeError {
    #[error("Struct missing: {}", .0)]
    StructMissing(Struct),
    #[error("Struct ability mismatch: {0:?} {1:?}")]
    StructAbilityMismatch(Struct, Struct),
    #[error("Struct type param mismatch: {0:?} {1:?}")]
    StructTypeParamMismatch(Struct, Struct),
    #[error("Struct field mismatch: {0:?} {1:?}")]
    StructFieldMismatch(Struct, Struct),
    #[error("Enum missing: {0:?}")]
    EnumMissing(Enum),
    #[error("Enum ability mismatch: {0:?} {1:?}")]
    EnumAbilityMismatch(Enum, Enum),
    #[error("Enum type param mismatch: {0:?} {1:?}")]
    EnumTypeParamMismatch(Enum, Enum),
    #[error("Enum new variant: {0:?} {1:?}")]
    EnumNewVariant(Enum, Enum),
    #[error("Enum variant missing: {0:?} {1:?}")]
    EnumVariantMissing(Enum, usize),
    #[error("Enum variant mismatch: {0:?} {1:?} {2:?}")]
    EnumVariantMismatch(Enum, Enum, usize),
    #[error("Function missing public: {0:?}")]
    FunctionMissingPublic(Function),
    #[error("Function missing friend: {0:?}")]
    FunctionMissingFriend(Function),
    #[error("Function missing entry: {0:?}")]
    FunctionMissingEntry(Function),
    #[error("Function signature mismatch: {0:?} {1:?}")]
    FunctionSignatureMismatch(Function, Function),
    #[error("Function lost public visibility: {0:?}")]
    FunctionLostPublicVisibility(Function),
    #[error("Function lost friend visibility: {0:?}")]
    FunctionLostFriendVisibility(Function),
    #[error("Function entry compatibility: {0:?} {1:?}")]
    FunctionEntryCompatibility(Function, Function),
    #[error("Friend module missing: {0:?} {1:?}")]
    FriendModuleMissing(BTreeSet<ModuleId>, BTreeSet<ModuleId>),
}

pub struct CliCompatibilityMode {
    errors: Vec<UpgradeCompatibilityModeError>,
}

impl Default for CliCompatibilityMode {
    fn default() -> Self {
        Self {
            errors: vec![],
        }
    }
}

impl CompatibilityMode for CliCompatibilityMode {
    type Error = anyhow::Error;
    // ignored, address is not populated pre-tx
    fn module_id_mismatch(&mut self, _old_addr: &AccountAddress, _old_name: &IdentStr, _new_addr: &AccountAddress, _new_name: &IdentStr) {}

    fn struct_missing(&mut self, old_struct: &Struct) {
        self.errors.push(UpgradeCompatibilityModeError::StructMissing(old_struct.clone()));
    }

    fn struct_ability_mismatch(&mut self, old_struct: &Struct, new_struct: &Struct) {
        self.errors.push(UpgradeCompatibilityModeError::StructAbilityMismatch(old_struct.clone(), new_struct.clone()));
    }

    fn struct_type_param_mismatch(&mut self, old_struct: &Struct, new_struct: &Struct) {
        self.errors.push(UpgradeCompatibilityModeError::StructTypeParamMismatch(old_struct.clone(), new_struct.clone()));
    }

    fn struct_field_mismatch(&mut self, old_struct: &Struct, new_struct: &Struct) {
        self.errors.push(UpgradeCompatibilityModeError::StructFieldMismatch(old_struct.clone(), new_struct.clone()));
    }

    fn enum_missing(&mut self, old_enum: &Enum) {
        self.errors.push(UpgradeCompatibilityModeError::EnumMissing(old_enum.clone()));
    }

    fn enum_ability_mismatch(&mut self, old_enum: &Enum, new_enum: &Enum) {
        self.errors.push(UpgradeCompatibilityModeError::EnumAbilityMismatch(old_enum.clone(), new_enum.clone()));
    }

    fn enum_type_param_mismatch(&mut self, old_enum: &Enum, new_enum: &Enum) {
        self.errors.push(UpgradeCompatibilityModeError::EnumTypeParamMismatch(old_enum.clone(), new_enum.clone()));
    }

    fn enum_new_variant(&mut self, old_enum: &Enum, new_enum: &Enum) {
        self.errors.push(UpgradeCompatibilityModeError::EnumNewVariant(old_enum.clone(), new_enum.clone()));
    }

    fn enum_variant_missing(&mut self, old_enum: &Enum, variant_idx: usize) {
        self.errors.push(UpgradeCompatibilityModeError::EnumVariantMissing(old_enum.clone(), variant_idx));
    }

    fn enum_variant_mismatch(&mut self, old_enum: &Enum, new_enum: &Enum, variant_idx: usize) {
        self.errors.push(UpgradeCompatibilityModeError::EnumVariantMismatch(old_enum.clone(), new_enum.clone(), variant_idx));
    }

    fn function_missing_public(&mut self, old_function: &Function) {
        self.errors.push(UpgradeCompatibilityModeError::FunctionMissingPublic(old_function.clone()));
    }

    fn function_missing_friend(&mut self, old_function: &Function) {
        self.errors.push(UpgradeCompatibilityModeError::FunctionMissingFriend(old_function.clone()));
    }

    fn function_missing_entry(&mut self, old_function: &Function) {
        self.errors.push(UpgradeCompatibilityModeError::FunctionMissingEntry(old_function.clone()));
    }

    fn function_signature_mismatch(&mut self, old_function: &Function, new_function: &Function) {
        self.errors.push(UpgradeCompatibilityModeError::FunctionSignatureMismatch(old_function.clone(), new_function.clone()));
    }

    fn function_lost_public_visibility(&mut self, old_function: &Function) {
        self.errors.push(UpgradeCompatibilityModeError::FunctionLostPublicVisibility(old_function.clone()));
    }

    fn function_lost_friend_visibility(&mut self, old_function: &Function) {
        self.errors.push(UpgradeCompatibilityModeError::FunctionLostFriendVisibility(old_function.clone()));
    }

    fn function_entry_compatibility(&mut self, old_function: &Function, new_function: &Function) {
        self.errors.push(UpgradeCompatibilityModeError::FunctionEntryCompatibility(old_function.clone(), new_function.clone()));
    }

    fn friend_module_missing(&mut self, old_modules: BTreeSet<ModuleId>, new_modules: BTreeSet<ModuleId>) {
        self.errors.push(UpgradeCompatibilityModeError::FriendModuleMissing(old_modules.clone(), new_modules.clone()));
    }

    fn finish(&self, _: &Compatibility) -> Result<(), Self::Error> {
        if !self.errors.is_empty() {
            let errors: Vec<String> = self.errors.iter().map(|e| format!("- {}", e)).collect();
            return Err(anyhow!("Upgrade compatibility check failed with the following errors:\n{}", errors.join("\n")));
        }
        Ok(())
    }
}
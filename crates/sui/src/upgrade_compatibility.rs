#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use std::collections::BTreeSet;
use move_binary_format::compatibility::{Compatibility};
use move_binary_format::compatibility_mode::{CompatibilityMode};
use move_binary_format::normalized::{Enum, Function, Struct};
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::{IdentStr, Identifier};
use thiserror::Error;
use anyhow::{anyhow};
use move_core_types::language_storage::ModuleId;
use sui_indexer::config::NameServiceOptions;

/// Errors that can occur during upgrade compatibility checks.
#[derive(Debug, Error)]
enum UpgradeCompatibilityModeError {
    #[error("Struct missing: {}", name.as_str())]
    StructMissing {
        name: Identifier,
        old_struct: Struct,
    },
    #[error("Struct ability mismatch: {}\n  Old: {:?}\n  New: {:?}", name.as_str(), old_struct.abilities, new_struct.abilities)]
    StructAbilityMismatch {
        name: Identifier,
        old_struct: Struct,
        new_struct: Struct,
    },
    #[error("Struct type param mismatch: {}\n  Old: {:?}\n  New: {:?}", name.as_str(), old_struct.type_parameters, new_struct.type_parameters)]
    StructTypeParamMismatch {
        name: Identifier,
        old_struct: Struct,
        new_struct: Struct,
    },
    #[error("Struct field mismatch: {}\n  Old: {:?}\n  New: {:?}", name.as_str(), old_struct.fields, new_struct.fields)]
    StructFieldMismatch {
        name: Identifier,
        old_struct: Struct,
        new_struct: Struct,
    },
    #[error("Enum missing: {}\n  {:?}", name.as_str(), old_enum)]
    EnumMissing {
        name: Identifier,
        old_enum: Enum,
    },
    #[error("Enum ability mismatch: {}\n  Old: {:?}\n  New: {:?}", name.as_str(), old_enum.abilities, new_enum.abilities)]
    EnumAbilityMismatch {
        name: Identifier,
        old_enum: Enum,
        new_enum: Enum,
    },
    #[error("Enum type param mismatch: {}\n  Old: {:?}\n  New: {:?}", name.as_str(), old_enum.type_parameters, new_enum.type_parameters)]
    EnumTypeParamMismatch {
        name: Identifier,
        old_enum: Enum,
        new_enum: Enum,
    },
    #[error("Enum new variant: {}\n  Old: {:?}\n  New: {:?}", name.as_str(), old_enum.variants, new_enum.variants)]
    EnumNewVariant {
        name: Identifier,
        old_enum: Enum,
        new_enum: Enum,
    },
    #[error("Enum variant missing: {}\n  {:?}", name.as_str(), old_enum.variants[*tag])]
    EnumVariantMissing {
        name: Identifier,
        old_enum: Enum,
        tag: usize,
    },
    #[error("Enum variant mismatch: {}\n  Old: {:?}\n  New: {:?}", name.as_str(), old_enum.variants[*tag], new_enum.variants[*tag])]
    EnumVariantMismatch {
        name: Identifier,
        old_enum: Enum,
        new_enum: Enum,
        tag: usize,
    },
    #[error("Function missing public: {}", name.as_str())]
    FunctionMissingPublic {
        name: Identifier,
        old_function: Function,
    },
    #[error("Function missing friend: {}", name.as_str())]
    FunctionMissingFriend {
        name: Identifier,
        old_function: Function,
    },
    #[error("Function missing entry: {}", name.as_str())]
    FunctionMissingEntry {
        name: Identifier,
        old_function: Function,
    },
    #[error("Function signature mismatch: {}\n  Old:\n    Params: {:?}\n    Return: {:?}\n  New:\n    Params: {:?}\n    Return: {:?}", name.as_str(),
        old_function.parameters, old_function.return_, new_function.parameters, new_function.return_
    )]
    FunctionSignatureMismatch {
        name: Identifier,
        old_function: Function,
        new_function: Function,
    },
    #[error("Function lost public visibility: {}", name.as_str())]
    FunctionLostPublicVisibility {
        name: Identifier,
        old_function: Function,
    },
    #[error("Function lost friend visibility: {}", name.as_str())]
    FunctionLostFriendVisibility {
        name: Identifier,
        old_function: Function,
    },
    #[error("Function entry compatibility: {}\n  Old: {:?}\n  New: {:?}", name.as_str(), old_function, new_function)]
    FunctionEntryCompatibility {
        name: Identifier,
        old_function: Function,
        new_function: Function,
    },
    #[error("Friend module missing: {0:?} {1:?}")]
    FriendModuleMissing(BTreeSet<ModuleId>, BTreeSet<ModuleId>),
}

/// A compatibility mode that collects errors
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

    fn struct_missing(&mut self, name: &Identifier, old_struct: &Struct) {
        println!("WOT");
        self.errors.push(UpgradeCompatibilityModeError::StructMissing{
            name: name.clone(),
            old_struct: old_struct.clone()
        });
    }

    fn struct_ability_mismatch(&mut self, name: &Identifier, old_struct: &Struct, new_struct: &Struct) {
        self.errors.push(UpgradeCompatibilityModeError::StructAbilityMismatch{
            name: name.clone(),
            old_struct: old_struct.clone(),
            new_struct: new_struct.clone()
        });
    }

    fn struct_type_param_mismatch(&mut self, name: &Identifier, old_struct: &Struct, new_struct: &Struct) {
        self.errors.push(UpgradeCompatibilityModeError::StructTypeParamMismatch {
            name: name.clone(),
            old_struct: old_struct.clone(),
            new_struct: new_struct.clone()
        });
    }

    fn struct_field_mismatch(&mut self, name: &Identifier, old_struct: &Struct, new_struct: &Struct) {
        self.errors.push(UpgradeCompatibilityModeError::StructFieldMismatch {
            name: name.clone(),
            old_struct: old_struct.clone(),
            new_struct: new_struct.clone()
        });
    }

    fn enum_missing(&mut self, name: &Identifier, old_enum: &Enum) {
        self.errors.push(UpgradeCompatibilityModeError::EnumMissing {
            name: name.clone(),
            old_enum: old_enum.clone()
        });
    }

    fn enum_ability_mismatch(&mut self, name: &Identifier, old_enum: &Enum, new_enum: &Enum) {
        self.errors.push(UpgradeCompatibilityModeError::EnumAbilityMismatch {
            name: name.clone(),
            old_enum: old_enum.clone(),
            new_enum: new_enum.clone()
        });
    }

    fn enum_type_param_mismatch(&mut self, name: &Identifier, old_enum: &Enum, new_enum: &Enum) {
        self.errors.push(UpgradeCompatibilityModeError::EnumTypeParamMismatch {
            name: name.clone(),
            old_enum: old_enum.clone(),
            new_enum: new_enum.clone()
        });
    }

    fn enum_new_variant(&mut self, name: &Identifier, old_enum: &Enum, new_enum: &Enum) {
        self.errors.push(UpgradeCompatibilityModeError::EnumNewVariant {
            name: name.clone(),
            old_enum: old_enum.clone(),
            new_enum: new_enum.clone()
        });
    }

    fn enum_variant_missing(&mut self, name: &Identifier, old_enum: &Enum, tag: usize) {
        self.errors.push(UpgradeCompatibilityModeError::EnumVariantMissing {
            name: name.clone(),
            old_enum: old_enum.clone(),
            tag,
        });
    }

    fn enum_variant_mismatch(&mut self, name: &Identifier, old_enum: &Enum, new_enum: &Enum, variant_idx: usize) {
        self.errors.push(UpgradeCompatibilityModeError::EnumVariantMismatch {
            name: name.clone(),
            old_enum: old_enum.clone(),
            new_enum: new_enum.clone(),
            tag: variant_idx
        });
    }

    fn function_missing_public(&mut self, name: &Identifier, old_function: &Function) {
        self.errors.push(UpgradeCompatibilityModeError::FunctionMissingPublic {
            name: name.clone(),
            old_function: old_function.clone()
        });
    }

    fn function_missing_friend(&mut self, name: &Identifier, old_function: &Function) {
        self.errors.push(UpgradeCompatibilityModeError::FunctionMissingFriend {
            name: name.clone(),
            old_function: old_function.clone()
        });
    }

    fn function_missing_entry(&mut self, name: &Identifier, old_function: &Function) {
        self.errors.push(UpgradeCompatibilityModeError::FunctionMissingEntry {
            name: name.clone(),
            old_function: old_function.clone()
        });
    }

    fn function_signature_mismatch(&mut self, name: &Identifier, old_function: &Function, new_function: &Function) {
        self.errors.push(UpgradeCompatibilityModeError::FunctionSignatureMismatch {
            name: name.clone(),
            old_function: old_function.clone(),
            new_function: new_function.clone()
        });
    }

    fn function_lost_public_visibility(&mut self, name: &Identifier, old_function: &Function) {
        self.errors.push(UpgradeCompatibilityModeError::FunctionLostPublicVisibility {
            name: name.clone(),
            old_function: old_function.clone()
        });
    }

    fn function_lost_friend_visibility(&mut self, name: &Identifier, old_function: &Function) {
        self.errors.push(UpgradeCompatibilityModeError::FunctionLostFriendVisibility {
            name: name.clone(),
            old_function: old_function.clone()
        });
    }

    fn function_entry_compatibility(&mut self, name: &Identifier, old_function: &Function, new_function: &Function) {
        self.errors.push(UpgradeCompatibilityModeError::FunctionEntryCompatibility {
            name: name.clone(),
            old_function: old_function.clone(),
            new_function: new_function.clone()
        });
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
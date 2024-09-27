// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[path = "unit_tests/upgrade_compatibility_tests.rs"]
#[cfg(test)]
mod upgrade_compatibility_tests;

use anyhow::{anyhow, Context, Error};
use std::collections::{BTreeSet, HashMap};
use thiserror::Error;

use move_binary_format::{
    compatibility::Compatibility,
    compatibility_mode::CompatibilityMode,
    file_format::Visibility,
    normalized::{Enum, Function, Module, Struct},
    CompiledModule,
};
use move_core_types::{
    account_address::AccountAddress,
    identifier::{IdentStr, Identifier},
    language_storage::ModuleId,
};
use sui_json_rpc_types::{SuiObjectDataOptions, SuiRawData};
use sui_protocol_config::ProtocolConfig;
use sui_sdk::SuiClient;
use sui_types::{base_types::ObjectID, execution_config_utils::to_binary_config};

/// Check the upgrade compatibility of a new package with an existing on-chain package.
pub async fn check_compatibility(
    client: &SuiClient,
    package_id: ObjectID,
    compiled_modules: &[Vec<u8>],
    protocol_config: ProtocolConfig,
) -> Result<(), Error> {
    let new_modules = compiled_modules
        .iter()
        .map(|b| CompiledModule::deserialize_with_config(b, &to_binary_config(&protocol_config)))
        .collect::<Result<Vec<_>, _>>()
        .context("Unable to to deserialize compiled module")?;

    let existing_obj_read = client
        .read_api()
        .get_object_with_options(package_id, SuiObjectDataOptions::new().with_bcs())
        .await
        .context("Unable to get existing package")?;

    let existing_obj = existing_obj_read
        .into_object()
        .context("Unable to get existing package")?
        .bcs
        .ok_or_else(|| anyhow!("Unable to read object"))?;

    let existing_package = match existing_obj {
        SuiRawData::Package(pkg) => Ok(pkg),
        SuiRawData::MoveObject(_) => Err(anyhow!("Object found when package expected")),
    }?;

    let existing_modules = existing_package
        .module_map
        .iter()
        .map(|m| CompiledModule::deserialize_with_config(m.1, &to_binary_config(&protocol_config)))
        .collect::<Result<Vec<_>, _>>()
        .context("Unable to get existing package")?;

    compare_packages(existing_modules, new_modules)
}

fn compare_packages(
    existing_modules: Vec<CompiledModule>,
    new_modules: Vec<CompiledModule>,
) -> Result<(), Error> {
    // create a map from the new modules
    let new_modules_map: HashMap<Identifier, CompiledModule> = new_modules
        .iter()
        .map(|m| (m.self_id().name().to_owned(), m.clone()))
        .collect();

    // for each existing find the new one run compatibility check
    for existing_module in existing_modules {
        let name = existing_module.self_id().name().to_owned();

        // find the new module with the same name
        match new_modules_map.get(&name) {
            Some(new_module) => {
                Compatibility::upgrade_check().check_with_mode::<CliCompatibilityMode>(
                    &Module::new(&existing_module),
                    &Module::new(new_module),
                )?;
            }
            None => {
                Err(anyhow!("Module {} is missing from the package", name))?;
            }
        }
    }

    Ok(())
}

/// Errors that can occur during upgrade compatibility checks.
/// one-to-one related to the underlying trait functions see: [`CompatibilityMode`]
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
    EnumMissing { name: Identifier, old_enum: Enum },
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

impl UpgradeCompatibilityModeError {
    fn breaks_compatibility(&self, compatability: &Compatibility) -> bool {
        match self {
            UpgradeCompatibilityModeError::StructAbilityMismatch { .. }
            | UpgradeCompatibilityModeError::StructTypeParamMismatch { .. }
            | UpgradeCompatibilityModeError::EnumAbilityMismatch { .. }
            | UpgradeCompatibilityModeError::EnumTypeParamMismatch { .. }
            | UpgradeCompatibilityModeError::FunctionMissingPublic { .. }
            | UpgradeCompatibilityModeError::FunctionLostPublicVisibility { .. } => {
                compatability.check_datatype_and_pub_function_linking
            }

            UpgradeCompatibilityModeError::StructFieldMismatch { .. }
            | UpgradeCompatibilityModeError::EnumVariantMissing { .. }
            | UpgradeCompatibilityModeError::EnumVariantMismatch { .. } => {
                compatability.check_datatype_layout
            }

            UpgradeCompatibilityModeError::StructMissing { .. }
            | UpgradeCompatibilityModeError::EnumMissing { .. } => {
                compatability.check_datatype_and_pub_function_linking
                    || compatability.check_datatype_layout
            }

            UpgradeCompatibilityModeError::FunctionSignatureMismatch { old_function, .. } => {
                if old_function.visibility == Visibility::Public {
                    return compatability.check_datatype_and_pub_function_linking;
                } else if old_function.visibility == Visibility::Friend {
                    return compatability.check_friend_linking;
                }
                if old_function.is_entry {
                    compatability.check_private_entry_linking
                } else {
                    false
                }
            }

            UpgradeCompatibilityModeError::FunctionMissingFriend { .. }
            | UpgradeCompatibilityModeError::FunctionLostFriendVisibility { .. }
            | UpgradeCompatibilityModeError::FriendModuleMissing(_, _) => {
                compatability.check_friend_linking
            }

            UpgradeCompatibilityModeError::FunctionMissingEntry { .. }
            | UpgradeCompatibilityModeError::FunctionEntryCompatibility { .. } => {
                compatability.check_private_entry_linking
            }
            UpgradeCompatibilityModeError::EnumNewVariant { .. } => {
                compatability.disallow_new_variants
            }
        }
    }
}

/// A compatibility mode that collects errors as a vector of enums which describe the error causes
#[derive(Default)]
pub struct CliCompatibilityMode {
    errors: Vec<UpgradeCompatibilityModeError>,
}

impl CompatibilityMode for CliCompatibilityMode {
    type Error = anyhow::Error;
    // ignored, address is not populated pre-tx
    fn module_id_mismatch(
        &mut self,
        _old_addr: &AccountAddress,
        _old_name: &IdentStr,
        _new_addr: &AccountAddress,
        _new_name: &IdentStr,
    ) {
    }

    fn struct_missing(&mut self, name: &Identifier, old_struct: &Struct) {
        self.errors
            .push(UpgradeCompatibilityModeError::StructMissing {
                name: name.clone(),
                old_struct: old_struct.clone(),
            });
    }

    fn struct_ability_mismatch(
        &mut self,
        name: &Identifier,
        old_struct: &Struct,
        new_struct: &Struct,
    ) {
        self.errors
            .push(UpgradeCompatibilityModeError::StructAbilityMismatch {
                name: name.clone(),
                old_struct: old_struct.clone(),
                new_struct: new_struct.clone(),
            });
    }

    fn struct_type_param_mismatch(
        &mut self,
        name: &Identifier,
        old_struct: &Struct,
        new_struct: &Struct,
    ) {
        self.errors
            .push(UpgradeCompatibilityModeError::StructTypeParamMismatch {
                name: name.clone(),
                old_struct: old_struct.clone(),
                new_struct: new_struct.clone(),
            });
    }

    fn struct_field_mismatch(
        &mut self,
        name: &Identifier,
        old_struct: &Struct,
        new_struct: &Struct,
    ) {
        self.errors
            .push(UpgradeCompatibilityModeError::StructFieldMismatch {
                name: name.clone(),
                old_struct: old_struct.clone(),
                new_struct: new_struct.clone(),
            });
    }

    fn enum_missing(&mut self, name: &Identifier, old_enum: &Enum) {
        self.errors
            .push(UpgradeCompatibilityModeError::EnumMissing {
                name: name.clone(),
                old_enum: old_enum.clone(),
            });
    }

    fn enum_ability_mismatch(&mut self, name: &Identifier, old_enum: &Enum, new_enum: &Enum) {
        self.errors
            .push(UpgradeCompatibilityModeError::EnumAbilityMismatch {
                name: name.clone(),
                old_enum: old_enum.clone(),
                new_enum: new_enum.clone(),
            });
    }

    fn enum_type_param_mismatch(&mut self, name: &Identifier, old_enum: &Enum, new_enum: &Enum) {
        self.errors
            .push(UpgradeCompatibilityModeError::EnumTypeParamMismatch {
                name: name.clone(),
                old_enum: old_enum.clone(),
                new_enum: new_enum.clone(),
            });
    }

    fn enum_new_variant(&mut self, name: &Identifier, old_enum: &Enum, new_enum: &Enum) {
        self.errors
            .push(UpgradeCompatibilityModeError::EnumNewVariant {
                name: name.clone(),
                old_enum: old_enum.clone(),
                new_enum: new_enum.clone(),
            });
    }

    fn enum_variant_missing(&mut self, name: &Identifier, old_enum: &Enum, tag: usize) {
        self.errors
            .push(UpgradeCompatibilityModeError::EnumVariantMissing {
                name: name.clone(),
                old_enum: old_enum.clone(),
                tag,
            });
    }

    fn enum_variant_mismatch(
        &mut self,
        name: &Identifier,
        old_enum: &Enum,
        new_enum: &Enum,
        variant_idx: usize,
    ) {
        self.errors
            .push(UpgradeCompatibilityModeError::EnumVariantMismatch {
                name: name.clone(),
                old_enum: old_enum.clone(),
                new_enum: new_enum.clone(),
                tag: variant_idx,
            });
    }

    fn function_missing_public(&mut self, name: &Identifier, old_function: &Function) {
        self.errors
            .push(UpgradeCompatibilityModeError::FunctionMissingPublic {
                name: name.clone(),
                old_function: old_function.clone(),
            });
    }

    fn function_missing_friend(&mut self, name: &Identifier, old_function: &Function) {
        self.errors
            .push(UpgradeCompatibilityModeError::FunctionMissingFriend {
                name: name.clone(),
                old_function: old_function.clone(),
            });
    }

    fn function_missing_entry(&mut self, name: &Identifier, old_function: &Function) {
        self.errors
            .push(UpgradeCompatibilityModeError::FunctionMissingEntry {
                name: name.clone(),
                old_function: old_function.clone(),
            });
    }

    fn function_signature_mismatch(
        &mut self,
        name: &Identifier,
        old_function: &Function,
        new_function: &Function,
    ) {
        self.errors
            .push(UpgradeCompatibilityModeError::FunctionSignatureMismatch {
                name: name.clone(),
                old_function: old_function.clone(),
                new_function: new_function.clone(),
            });
    }

    fn function_lost_public_visibility(&mut self, name: &Identifier, old_function: &Function) {
        self.errors.push(
            UpgradeCompatibilityModeError::FunctionLostPublicVisibility {
                name: name.clone(),
                old_function: old_function.clone(),
            },
        );
    }

    fn function_lost_friend_visibility(&mut self, name: &Identifier, old_function: &Function) {
        self.errors.push(
            UpgradeCompatibilityModeError::FunctionLostFriendVisibility {
                name: name.clone(),
                old_function: old_function.clone(),
            },
        );
    }

    fn function_entry_compatibility(
        &mut self,
        name: &Identifier,
        old_function: &Function,
        new_function: &Function,
    ) {
        self.errors
            .push(UpgradeCompatibilityModeError::FunctionEntryCompatibility {
                name: name.clone(),
                old_function: old_function.clone(),
                new_function: new_function.clone(),
            });
    }

    fn friend_module_missing(
        &mut self,
        old_modules: BTreeSet<ModuleId>,
        new_modules: BTreeSet<ModuleId>,
    ) {
        self.errors
            .push(UpgradeCompatibilityModeError::FriendModuleMissing(
                old_modules.clone(),
                new_modules.clone(),
            ));
    }

    fn finish(&self, compatability: &Compatibility) -> Result<(), Self::Error> {
        let errors: Vec<String> = self
            .errors
            .iter()
            .filter(|e| e.breaks_compatibility(compatability))
            .map(|e| format!("- {}", e))
            .collect();

        if !errors.is_empty() {
            return Err(anyhow!(
                "Upgrade compatibility check failed with the following errors:\n{}",
                errors.join("\n")
            ));
        }
        Ok(())
    }
}

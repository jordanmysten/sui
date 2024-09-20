use move_binary_format::compatibility::{Compatibility, CompatibilityMode};
use move_binary_format::normalized::{Enum, Function, Struct};
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::IdentStr;

struct CLICompatabilityMode {
    structs_missing_errors: Vec<String>,
    struct_ability_mismatch_errors: Vec<String>,
    struct_type_param_mismatch_errors: Vec<String>,
    struct_field_mismatch_errors: Vec<String>,
    enum_missing_errors: Vec<String>,
    enum_ability_mismatch_errors: Vec<String>,
    enum_type_param_mismatch_errors: Vec<String>,
    enum_new_variant_errors: Vec<String>,
    enum_variant_mismatch_errors: Vec<String>,
    enum_variant_missing_errors: Vec<String>,
    function_missing_errors: Vec<String>,
    function_friend_missing_errors: Vec<String>,
    function_friend_linking_errors: Vec<String>,
    function_previously_friend_errors: Vec<String>,
    function_visibility_mismatch_errors: Vec<String>,
    function_entry_compatibility_errors: Vec<String>,

}

impl Default for CLICompatabilityMode {
    fn default() -> Self {
        Self {
            structs_missing_errors: vec![],
            struct_ability_mismatch_errors: vec![],
            struct_type_param_mismatch_errors: vec![],
            struct_field_mismatch_errors: vec![],
            enum_missing_errors: vec![],
            enum_ability_mismatch_errors: vec![],
            enum_type_param_mismatch_errors: vec![],
            enum_new_variant_errors: vec![],
            enum_variant_mismatch_errors: vec![],
            enum_variant_missing_errors: vec![],
            function_missing_errors: vec![],
            function_friend_missing_errors: vec![],
            function_friend_linking_errors: vec![],
            function_previously_friend_errors: vec![],
            function_visibility_mismatch_errors: vec![],
            function_entry_compatibility_errors: vec![],
        }
    }
}

impl CompatibilityMode for CLICompatabilityMode {
    type Error = anyhow::Error;
    // ignored, address is not populated pre-tx
    fn module_id_mismatch(&mut self, old_addr: &AccountAddress, old_name: &IdentStr, new_addr: &AccountAddress, new_name: &IdentStr) {}

    fn struct_missing(&mut self, addr: &AccountAddress) {
        self.structs_missing_errors.push(format!("{}::{}", addr, name));
    }

    fn struct_ability_mismatch(&mut self, old_struct: &Struct, new_struct: &Struct) {
        self.struct_ability_mismatch_errors.push(format!("{}::{}", old_struct.module, old_struct.name));
    }

    fn struct_type_param_mismatch(&mut self, old_struct: &Struct, new_struct: &Struct) {
        self.struct_type_param_mismatch_errors.push(format!("{}::{}", old_struct.module, old_struct.name));
    }

    fn struct_field_mismatch(&mut self, old_struct: &Struct, new_struct: &Struct) {
        self.struct_field_mismatch_errors.push(format!("{}::{}", old_struct.module, old_struct.name));
    }

    fn enum_missing(&mut self, old_enum: &Enum) {
        self.enum_missing_errors.push(format!("{}::{}", old_enum.module, old_enum.name));
    }

    fn enum_ability_mismatch(&mut self, old_enum: &Enum, new_enum: &Enum) {
        self.enum_ability_mismatch_errors.push(format!("{}::{}", old_enum.module, old_enum.name));
    }

    fn enum_type_param_mismatch(&mut self, old_enum: &Enum, new_enum: &Enum) {
        self.enum_type_param_mismatch_errors.push(format!("{}::{}", old_enum.module, old_enum.name));
    }

    fn enum_new_variant(&mut self, old_enum: &Enum, new_enum: &Enum) {
        self.enum_new_variant_errors.push(format!("{}::{}", old_enum.module, old_enum.name));
    }

    fn enum_variant_mismatch(&mut self, old_enum: &Enum, new_enum: &Enum) {
        self.enum_variant_mismatch_errors.push(format!("{}::{}", old_enum.module, old_enum.name));
    }

    fn enum_variant_missing(&mut self, old_enum: &Enum) {
        self.enum_variant_missing_errors.push(format!("{}::{}", old_enum.module, old_enum.name));
    }


    fn function_missing(&mut self, old_func: &Function, check_private_entry_linking: bool) {
        self.function_missing_errors.push(format!("{}::{}", old_func.module, old_func.name));
    }

    fn function_friend_missing(&mut self) {
        self.function_friend_missing_errors.push(format!("{}::{}", old_func.module, old_func.name));
    }

    fn function_friend_linking(&mut self, old_func: &Function) {
        self.function_friend_linking_errors.push(format!("{}::{}", old_func.module, old_func.name));
    }

    fn function_previously_friend(&mut self, old_func: &Function) {
        self.function_previously_friend_errors.push(format!("{}::{}", old_func.module, old_func.name));
    }

    fn function_visibility_mismatch(&mut self, old_func: &Function, new_func: &Function) {
        self.function_visibility_mismatch_errors.push(format!("{}::{}", old_func.module, old_func.name));
    }

    fn function_entry_compatibility(&mut self, old_func: &Function, new_func: &Function) {
        self.function_entry_compatibility_errors.push(format!("{}::{}", old_func.module, old_func.name));
    }

    fn finish(&self, _: &Compatibility) -> Result<(), Self::Error> {
        let mut errors = vec![];
        if !self.structs_missing_errors.is_empty() {
            errors.push(format!("Structs missing: {:?}", self.structs_missing_errors));
        }
        if !self.struct_ability_mismatch_errors.is_empty() {
            errors.push(format!("Structs ability mismatch: {:?}", self.struct_ability_mismatch_errors));
        }
        if !self.struct_type_param_mismatch_errors.is_empty() {
            errors.push(format!("Structs type param mismatch: {:?}", self.struct_type_param_mismatch_errors));
        }
        if !self.struct_field_mismatch_errors.is_empty() {
            errors.push(format!("Structs field mismatch: {:?}", self.struct_field_mismatch_errors));
        }
        if !self.enum_missing_errors.is_empty() {
            errors.push(format!("Enums missing: {:?}", self.enum_missing_errors));
        }
        if !self.enum_ability_mismatch_errors.is_empty() {
            errors.push(format!("Enums ability mismatch: {:?}", self.enum_ability_mismatch_errors));
        }
        if !self.enum_type_param_mismatch_errors.is_empty() {
            errors.push(format!("Enums type param mismatch: {:?}", self.enum_type_param_mismatch_errors));
        }
        if !self.enum_new_variant_errors.is_empty() {
            errors.push(format!("Enums new variant: {:?}", self.enum_new_variant_errors));
        }
        if !self.enum_variant_mismatch_errors.is_empty() {
            errors.push(format!("Enums variant mismatch: {:?}", self.enum_variant_mismatch_errors));
        }
        if !self.enum_variant_missing_errors.is_empty() {
            errors.push(format!("Enums variant missing: {:?}", self.enum_variant_missing_errors));
        }
        if !self.function_missing_errors.is_empty() {
            errors.push(format!("Functions missing: {:?}", self.function_missing_errors));
        }
        if !self.function_friend_missing_errors.is_empty() {
            errors.push(format!("Functions friend missing: {:?}", self.function_friend_missing_errors));
        }
        if !self.function_friend_linking_errors.is_empty() {
            errors.push(format!("Functions friend linking: {:?}", self.function_friend_linking_errors));
        }
        if !self.function_previously_friend_errors.is_empty() {
            errors.push(format!("Functions previously friend: {:?}", self.function_previously_friend_errors));
        }
        if !self.function_visibility_mismatch_errors.is_empty() {
            errors.push(format!("Functions visibility mismatch: {:?}", self.function_visibility_mismatch_errors));
        }
        if !self.function_entry_compatibility_errors.is_empty() {
            errors.push(format!("Functions entry compatibility: {:?}", self.function_entry_compatibility_errors));
        }
        if !self.function_entry_compatibility_errors.is_empty() {
            errors.push(format!("Functions entry compatibility: {:?}", self.function_entry_compatibility_errors));
        }

        if errors.len() {
            return Err(anyhow::anyhow!(errors.join("\n")));
        }

        Ok(())

    }
}
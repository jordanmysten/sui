// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::upgrade_compatibility::compare_packages;
use move_binary_format::CompiledModule;
use std::path::PathBuf;
use sui_move_build::BuildConfig;

#[test]
fn test_all_fail() {
    let (pkg_v1, pkg_v2) = get_packages("all");

    let result = compare_packages(pkg_v1, pkg_v2);
    assert!(result.is_err());
    let err = result.unwrap_err();

    assert_eq!(
        err.to_string(),
        r#"Upgrade compatibility check failed with the following errors:
- Struct ability mismatch: StructAbilityMismatchAdd
  Old: []
  New: [Copy, ]
- Struct ability mismatch: StructAbilityMismatchChange
  Old: [Copy, ]
  New: [Drop, ]
- Struct ability mismatch: StructAbilityMismatchRemove
  Old: [Copy, ]
  New: []
- Struct field mismatch: StructFieldMismatchAdd
  Old: [Field { name: Identifier("a"), type_: U64 }, Field { name: Identifier("b"), type_: U64 }]
  New: [Field { name: Identifier("a"), type_: U64 }, Field { name: Identifier("b"), type_: U64 }, Field { name: Identifier("c"), type_: U64 }]
- Struct field mismatch: StructFieldMismatchChange
  Old: [Field { name: Identifier("a"), type_: U64 }, Field { name: Identifier("b"), type_: U64 }]
  New: [Field { name: Identifier("a"), type_: U64 }, Field { name: Identifier("b"), type_: U8 }]
- Struct field mismatch: StructFieldMismatchRemove
  Old: [Field { name: Identifier("a"), type_: U64 }, Field { name: Identifier("b"), type_: U64 }]
  New: [Field { name: Identifier("a"), type_: U64 }]
- Struct missing: StructToBeRemoved
- Struct type param mismatch: StructTypeParamMismatch
  Old: [DatatypeTyParameter { constraints: [], is_phantom: false }, DatatypeTyParameter { constraints: [], is_phantom: false }]
  New: [DatatypeTyParameter { constraints: [], is_phantom: false }]
- Enum ability mismatch: EnumAbilityMismatchAdd
  Old: []
  New: [Copy, ]
- Enum ability mismatch: EnumAbilityMismatchChange
  Old: [Copy, ]
  New: [Drop, ]
- Enum ability mismatch: EnumAbilityMismatchRemove
  Old: [Copy, ]
  New: []
- Enum new variant: EnumNewVariant
  Old: [Variant { name: Identifier("A"), fields: [] }, Variant { name: Identifier("B"), fields: [] }, Variant { name: Identifier("C"), fields: [] }]
  New: [Variant { name: Identifier("A"), fields: [] }, Variant { name: Identifier("B"), fields: [] }, Variant { name: Identifier("C"), fields: [] }, Variant { name: Identifier("D"), fields: [] }]
- Enum missing: EnumToBeRemoved
  Enum { abilities: [], type_parameters: [], variants: [Variant { name: Identifier("A"), fields: [] }, Variant { name: Identifier("B"), fields: [] }] }
- Enum variant missing: EnumVariantMissing
  Variant { name: Identifier("B"), fields: [] }
- Function signature mismatch: function_add_arg
  Old:
    Params: []
    Return: []
  New:
    Params: [U64]
    Return: []
- Function signature mismatch: function_change_arg
  Old:
    Params: [U64]
    Return: []
  New:
    Params: [U8]
    Return: []
- Function signature mismatch: function_remove_arg
  Old:
    Params: [U64]
    Return: []
  New:
    Params: []
    Return: []
- Function lost public visibility: function_to_have_public_removed"#
    )
}

#[test]
fn test_struct_missing() {
    let (pkg_v1, pkg_v2) = get_packages("struct_missing");
    let result = compare_packages(pkg_v1, pkg_v2);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.to_string(), "Upgrade compatibility check failed with the following errors:\n- Struct missing: StructToBeRemoved");
}

#[test]
fn test_friend_link_ok() {
    let (pkg_v1, pkg_v2) = get_packages("friend_linking");
    // upgrade compatibility ignores friend linking
    assert!(compare_packages(pkg_v1, pkg_v2).is_ok());
}

#[test]
fn test_entry_linking_ok() {
    let (pkg_v1, pkg_v2) = get_packages("entry_linking");
    // upgrade compatibility ignores entry linking
    assert!(compare_packages(pkg_v1, pkg_v2).is_ok());
}

fn get_packages(name: &str) -> (Vec<CompiledModule>, Vec<CompiledModule>) {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("src/unit_tests/fixtures/upgrade_errors/");
    path.push(format!("{}_v1", name));

    let pkg_v1 = BuildConfig::new_for_testing()
        .build(&path)
        .unwrap()
        .into_modules();

    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("src/unit_tests/fixtures/upgrade_errors/");
    path.push(format!("{}_v2", name));

    let pkg_v2 = BuildConfig::new_for_testing()
        .build(&path)
        .unwrap()
        .into_modules();

    (pkg_v1, pkg_v2)
}

// Copyright (c), Mysten Labs, Inc.
// Copyright (c), The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0
use crate::errors::InternalError;
use crate::return_err;
use crate::KeyId;
use crypto::create_full_id;
use fastcrypto::encoding::{Base64, Encoding};
use myso_sdk::types::transaction::{
    Argument, CallArg, Command, ObjectArg, ProgrammableTransaction,
};
use myso_types::base_types::ObjectID;
use myso_types::transaction::ProgrammableMoveCall;
use tracing::debug;

///
/// PTB that is valid for evaluating a policy. See restrictions in try_from below.
///
pub struct ValidPtb(ProgrammableTransaction);

// Should only increase this with time.
const MAX_COMMANDS: usize = 100;

/// The memory read gates keep their historical names (not `mydata_approve*`) but follow the
/// key-server convention: the key id is the FIRST argument, then `MemoryConfig`, the
/// `MemoryAccount` and, for the org gate, the organization and its share group. Only these two
/// read gates qualify.
fn memory_policy_layout(cmd: &ProgrammableMoveCall) -> bool {
    cmd.module.as_str() == "memory"
        && cmd.type_arguments.is_empty()
        && match cmd.function.as_str() {
            "approve_key_policy" => cmd.arguments.len() == 4,
            "approve_org_key_policy" => cmd.arguments.len() == 6,
            _ => false,
        }
}

pub struct MemoryPolicyBinding {
    pub package: ObjectID,
    pub account: ObjectID,
    pub organization: Option<ObjectID>,
    id: KeyId,
}

impl MemoryPolicyBinding {
    /// Memory encryption ids have a random prefix followed by the owner/org
    /// address. Bind the requested key to that namespace before running Move.
    pub fn validate_namespace(&self, namespace: &[u8]) -> Result<(), InternalError> {
        if namespace.len() != 32 || !self.id.ends_with(namespace) {
            return Err(InternalError::InvalidPTB(
                "Memory key id does not match the account or organization namespace".into(),
            ));
        }
        Ok(())
    }
}

fn object_argument(
    ptb: &ProgrammableTransaction,
    arg: &Argument,
) -> Result<ObjectID, InternalError> {
    let Argument::Input(index) = arg else {
        return Err(InternalError::InvalidPTB(
            "Memory policy requires object inputs".into(),
        ));
    };
    match ptb.inputs.get(*index as usize) {
        Some(CallArg::Object(ObjectArg::SharedObject { id, .. })) => Ok(*id),
        Some(CallArg::Object(ObjectArg::ImmOrOwnedObject((id, ..)))) => Ok(*id),
        _ => Err(InternalError::InvalidPTB(
            "Memory policy requires object inputs".into(),
        )),
    }
}

fn memory_policy_binding(
    ptb: &ProgrammableTransaction,
    cmd: &ProgrammableMoveCall,
) -> Result<Option<MemoryPolicyBinding>, InternalError> {
    if !memory_policy_layout(cmd) {
        return Ok(None);
    }
    // Ensure the alternate layout is an actual config/account approval call,
    // rather than an arbitrary pure input masquerading as an object.
    object_argument(ptb, &cmd.arguments[1])?;
    let account = object_argument(ptb, &cmd.arguments[2])?;
    let organization = if cmd.function.as_str() == "approve_org_key_policy" {
        object_argument(ptb, &cmd.arguments[4])?;
        Some(object_argument(ptb, &cmd.arguments[3])?)
    } else {
        None
    };
    Ok(Some(MemoryPolicyBinding {
        package: cmd.package,
        account,
        organization,
        id: get_key_id(ptb, cmd)?,
    }))
}

impl TryFrom<ProgrammableTransaction> for ValidPtb {
    type Error = InternalError;

    fn try_from(ptb: ProgrammableTransaction) -> Result<Self, Self::Error> {
        debug!("Creating vptb from: {:?}", ptb);

        // Restriction: The PTB must not have more than MAX_COMMANDS commands (MAX_COMMANDS may
        // increase in the future).
        if ptb.commands.len() > MAX_COMMANDS {
            return_err!(
                InternalError::InvalidPTB(format!(
                    "Too many commands in PTB (more than {MAX_COMMANDS})"
                )),
                "Too many commands in PTB: {:?}",
                ptb
            );
        }

        // Restriction: The PTB must have at least one input and one command.
        if ptb.inputs.is_empty() || ptb.commands.is_empty() {
            return_err!(
                InternalError::InvalidPTB("Empty PTB input or command".to_string()),
                "Invalid PTB {:?}",
                ptb
            );
        }

        // Checked above that there is at least one command
        let Command::MoveCall(first_cmd) = &ptb.commands[0] else {
            return_err!(
                InternalError::InvalidPTB("Invalid first command".to_string()),
                "Invalid PTB first command {:?}",
                ptb
            );
        };
        let pkg_id = first_cmd.package;

        for cmd in &ptb.commands {
            // Restriction: All commands must be a MoveCall.
            let Command::MoveCall(cmd) = &cmd else {
                return_err!(
                    InternalError::InvalidPTB("Non MoveCall command".to_string()),
                    "Non MoveCall command {:?}",
                    cmd
                );
            };

            // Every policy puts the id first; the memory read gates additionally get their
            // config/account/organization inputs validated as objects.
            let _ = get_key_id(&ptb, cmd)?;
            memory_policy_binding(&ptb, cmd)?;

            // Restriction: mydata_approve* or the two exact deployed memory read hooks.
            // Restriction: All commands in the PTB must use the same package id.
            if (!cmd.function.starts_with("mydata_approve") && !memory_policy_layout(cmd))
                || cmd.package != pkg_id
            {
                return_err!(
                    InternalError::InvalidPTB("Invalid function or package id".to_string()),
                    "Invalid function or package id {:?}",
                    cmd
                );
            }
        }

        Ok(ValidPtb(ptb))
    }
}

fn get_key_id(
    ptb: &ProgrammableTransaction,
    cmd: &ProgrammableMoveCall,
) -> Result<KeyId, InternalError> {
    if cmd.arguments.is_empty() {
        return_err!(
            InternalError::InvalidPTB("Empty args".to_string()),
            "Invalid PTB command {:?}",
            cmd
        );
    }
    let Argument::Input(arg_idx) = cmd.arguments[0] else {
        return_err!(
            InternalError::InvalidPTB("Invalid index for first argument".to_string()),
            "Invalid PTB command {:?}",
            cmd
        );
    };
    let Some(CallArg::Pure(id)) = &ptb.inputs.get(arg_idx as usize) else {
        return_err!(
            InternalError::InvalidPTB("Invalid first parameter for mydata_approve".to_string()),
            "Invalid PTB command {:?}",
            cmd
        );
    };
    bcs::from_bytes(id).map_err(|_| {
        InternalError::InvalidPTB("Invalid BCS for first parameter for mydata_approve".to_string())
    })
}

impl ValidPtb {
    pub fn memory_policy_bindings(&self) -> Vec<MemoryPolicyBinding> {
        self.0
            .commands
            .iter()
            .filter_map(|cmd| {
                let Command::MoveCall(cmd) = cmd else {
                    unreachable!()
                };
                memory_policy_binding(&self.0, cmd).expect("validated above")
            })
            .collect()
    }
    pub fn try_from_base64(s: &str) -> Result<Self, InternalError> {
        Base64::decode(s)
            .map_err(|_| InternalError::InvalidPTB("Invalid Base64".to_string()))
            .and_then(|b| {
                bcs::from_bytes::<ProgrammableTransaction>(&b)
                    .map_err(|_| InternalError::InvalidPTB("Invalid BCS".to_string()))
            })
            .and_then(ValidPtb::try_from)
    }

    // The ids without the pkgId prefix
    pub fn inner_ids(&self) -> Vec<KeyId> {
        self.0
            .commands
            .iter()
            .map(|cmd| {
                let Command::MoveCall(cmd) = cmd else {
                    unreachable!()
                };
                get_key_id(&self.0, cmd).expect("checked above")
            })
            .collect()
    }

    pub fn pkg_id(&self) -> ObjectID {
        let Command::MoveCall(cmd) = &self.0.commands[0] else {
            unreachable!()
        };
        cmd.package
    }

    pub fn full_ids(&self, first_pkg_id: &ObjectID) -> Vec<KeyId> {
        self.inner_ids()
            .iter()
            .map(|inner_id| create_full_id(&first_pkg_id.into_bytes(), inner_id))
            .collect()
    }

    pub fn ptb(&self) -> &ProgrammableTransaction {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myso_sdk::types::base_types::MySoAddress;
    use myso_types::base_types::ObjectID;
    use myso_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
    use myso_types::Identifier;

    #[test]
    fn test_valid() {
        let mut builder = ProgrammableTransactionBuilder::new();
        let id = vec![1u8, 2, 3, 4];
        let id_caller = builder.pure(id.clone()).unwrap();
        let pkgid = ObjectID::random();
        builder.programmable_move_call(
            pkgid,
            Identifier::new("bla").unwrap(),
            Identifier::new("mydata_approve_x").unwrap(),
            vec![],
            vec![id_caller],
        );
        builder.programmable_move_call(
            pkgid,
            Identifier::new("bla2").unwrap(),
            Identifier::new("mydata_approve_y").unwrap(),
            vec![],
            vec![id_caller],
        );
        let ptb = builder.finish();
        let valid_ptb = ValidPtb::try_from(ptb).unwrap();

        assert_eq!(valid_ptb.inner_ids(), vec![id.clone(), id]);
        assert_eq!(valid_ptb.pkg_id(), pkgid);
    }

    fn memory_ptb(function: &str, module: &str, namespace: ObjectID) -> ProgrammableTransaction {
        use myso_types::transaction::SharedObjectMutability;
        let mut builder = ProgrammableTransactionBuilder::new();
        let mut args = Vec::new();
        let config = builder
            .obj(ObjectArg::SharedObject {
                id: ObjectID::random(),
                initial_shared_version: 1.into(),
                mutability: SharedObjectMutability::Immutable,
            })
            .unwrap();
        let mut id = vec![7u8; 16];
        id.extend_from_slice(&namespace.into_bytes());
        let id = builder.pure(id).unwrap();
        let account = builder
            .obj(ObjectArg::SharedObject {
                id: ObjectID::random(),
                initial_shared_version: 1.into(),
                mutability: SharedObjectMutability::Immutable,
            })
            .unwrap();
        args.extend([id, config, account]);
        if function == "approve_org_key_policy" {
            args.push(
                builder
                    .obj(ObjectArg::SharedObject {
                        id: namespace,
                        initial_shared_version: 1.into(),
                        mutability: SharedObjectMutability::Immutable,
                    })
                    .unwrap(),
            );
            args.push(
                builder
                    .obj(ObjectArg::SharedObject {
                        id: ObjectID::random(),
                        initial_shared_version: 1.into(),
                        mutability: SharedObjectMutability::Immutable,
                    })
                    .unwrap(),
            );
        }
        args.push(
            builder
                .obj(ObjectArg::SharedObject {
                    id: ObjectID::random(),
                    initial_shared_version: 1.into(),
                    mutability: SharedObjectMutability::Immutable,
                })
                .unwrap(),
        );
        builder.programmable_move_call(
            ObjectID::random(),
            Identifier::new(module).unwrap(),
            Identifier::new(function).unwrap(),
            vec![],
            args,
        );
        builder.finish()
    }

    #[test]
    fn memory_read_hooks_extract_the_first_argument_and_bind_namespace() {
        for function in ["approve_key_policy", "approve_org_key_policy"] {
            let namespace = ObjectID::random();
            let valid = ValidPtb::try_from(memory_ptb(function, "memory", namespace)).unwrap();
            assert_eq!(valid.inner_ids()[0].len(), 48);
            let bindings = valid.memory_policy_bindings();
            assert_eq!(bindings.len(), 1);
            assert!(bindings[0]
                .validate_namespace(&namespace.into_bytes())
                .is_ok());
            assert!(bindings[0]
                .validate_namespace(&ObjectID::random().into_bytes())
                .is_err());
            assert_eq!(
                bindings[0].organization,
                (function == "approve_org_key_policy").then_some(namespace)
            );
        }
    }

    #[test]
    fn memory_compatibility_does_not_admit_other_modules_or_write_hooks() {
        assert!(ValidPtb::try_from(memory_ptb(
            "approve_key_policy",
            "other_module",
            ObjectID::random()
        ))
        .is_err());
        assert!(ValidPtb::try_from(memory_ptb(
            "approve_key_write_policy",
            "memory",
            ObjectID::random()
        ))
        .is_err());
    }

    #[test]
    fn memory_hook_rejects_config_disguised_as_a_pure_input() {
        let mut ptb = memory_ptb("approve_key_policy", "memory", ObjectID::random());
        ptb.inputs[0] = CallArg::Pure(vec![1]);
        assert!(ValidPtb::try_from(ptb).is_err());
    }

    #[test]
    fn test_invalid_empty_ptb() {
        let builder = ProgrammableTransactionBuilder::new();
        let ptb = builder.finish();
        assert_eq!(
            ValidPtb::try_from(ptb).err(),
            Some(InternalError::InvalidPTB(
                "Empty PTB input or command".to_string()
            ))
        );
    }

    #[test]
    fn test_invalid_no_inputs() {
        let mut builder = ProgrammableTransactionBuilder::new();
        let pkgid = ObjectID::random();
        builder.programmable_move_call(
            pkgid,
            Identifier::new("bla").unwrap(),
            Identifier::new("mydata_approve").unwrap(),
            vec![],
            vec![],
        );
        let ptb = builder.finish();
        assert_eq!(
            ValidPtb::try_from(ptb).err(),
            Some(InternalError::InvalidPTB(
                "Empty PTB input or command".to_string()
            ))
        );
    }

    #[test]
    fn test_invalid_non_move_call() {
        let mut builder = ProgrammableTransactionBuilder::new();
        let sender = MySoAddress::random_for_testing_only();
        let id = vec![1u8, 2, 3, 4];
        let id_caller = builder.pure(id.clone()).unwrap();
        let pkgid = ObjectID::random();

        builder.programmable_move_call(
            pkgid,
            Identifier::new("bla").unwrap(),
            Identifier::new("mydata_approve_x").unwrap(),
            vec![],
            vec![id_caller],
        );
        // Add a transfer command instead of move call
        builder.transfer_myso(sender, Some(1));
        let ptb = builder.finish();
        assert_eq!(
            ValidPtb::try_from(ptb).err(),
            Some(InternalError::InvalidPTB(
                "Non MoveCall command".to_string()
            ))
        );
    }

    #[test]
    fn test_invalid_different_package_ids() {
        let mut builder = ProgrammableTransactionBuilder::new();
        let id = builder.pure(vec![1u8, 2, 3]).unwrap();
        let pkgid1 = ObjectID::random();
        let pkgid2 = ObjectID::random();
        builder.programmable_move_call(
            pkgid1,
            Identifier::new("bla").unwrap(),
            Identifier::new("mydata_approve").unwrap(),
            vec![],
            vec![id],
        );
        builder.programmable_move_call(
            pkgid2, // Different package ID
            Identifier::new("bla").unwrap(),
            Identifier::new("mydata_approve").unwrap(),
            vec![],
            vec![id],
        );
        let ptb = builder.finish();
        assert_eq!(
            ValidPtb::try_from(ptb).err(),
            Some(InternalError::InvalidPTB(
                "Invalid function or package id".to_string()
            ))
        );
    }
}

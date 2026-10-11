// Copyright (c), The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

use crypto::elgamal;
use crypto::EncryptedObject;
use crypto::ObjectID;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::encoding::{Base64, Encoding, Hex};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::{KeyPair, Signer};
use mydata_sdk::types::FetchKeyResponse;
use mydata_sdk::{decrypt_mydata_responses, signed_message, signed_request, IBEPublicKey};
use myso_keys::keystore::AccountKeystore;
use myso_sdk::wallet_context::WalletContext;
use myso_sdk::MySoClientBuilder;
use myso_sdk_types::ProgrammableTransaction as SdkProgrammableTransaction;
use myso_types::signature::GenericSignature;
use myso_types::crypto::Signature as MySoSignature;
use myso_types::object::Owner;
use myso_types::base_types::{MySoAddress, ObjectID as TypesObjectID};
use myso_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
use myso_types::transaction::{
    ObjectArg, ProgrammableTransaction, SharedObjectMutability,
};
use myso_types::Identifier;
use rand::thread_rng;
use reqwest::Body;
use serde_json::json;
use shared_crypto::intent::{Intent, PersonalMessage};
use std::collections::HashMap;
use std::path::PathBuf;

const TTL_MIN: u16 = 10;

pub struct FetchProfileSubscriptionParams {
    pub rpc_url: String,
    pub key_server_url: String,
    pub key_server_object_id: ObjectID,
    pub server_public_key_hex: String,
    pub package_id: ObjectID,
    pub encrypted_object_hex: String,
    pub encryption_id_hex: String,
    pub sender: MySoAddress,
    pub client_config: Option<PathBuf>,
    pub memory_config_id: ObjectID,
    pub mydata_id: ObjectID,
    pub memory_account_id: ObjectID,
    pub service_id: ObjectID,
    pub subscription_id: ObjectID,
    pub clock_id: ObjectID,
    pub block_list_registry_id: ObjectID,
}

pub async fn fetch_and_decrypt_profile_subscription(
    params: FetchProfileSubscriptionParams,
) -> FastCryptoResult<Vec<u8>> {
    let client = MySoClientBuilder::default()
        .build(&params.rpc_url)
        .await
        .map_err(|e| FastCryptoError::GeneralError(format!("RPC client: {e}")))?;

    let ptb = build_profile_subscription_policy_ptb(
        &client,
        to_types_oid(params.package_id),
        Hex::decode(params.encryption_id_hex.trim_start_matches("0x"))
            .map_err(|e| FastCryptoError::GeneralError(format!("encryption id: {e}")))?,
        to_types_oid(params.memory_config_id),
        to_types_oid(params.mydata_id),
        to_types_oid(params.memory_account_id),
        to_types_oid(params.service_id),
        to_types_oid(params.subscription_id),
        to_types_oid(params.clock_id),
        to_types_oid(params.block_list_registry_id),
    )
    .await?;

    let wallet = load_wallet(params.client_config.as_deref(), Some(params.sender))?;

    let mut rng = thread_rng();
    let (enc_secret, enc_key, enc_verification_key) = elgamal::genkey(&mut rng);
    let session = Ed25519KeyPair::generate(&mut rng);

    let creation_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| FastCryptoError::GeneralError(e.to_string()))?
        .as_millis() as u64;

    let package_name = to_types_oid(params.package_id).to_hex_uncompressed();
    let message = signed_message(
        package_name,
        session.public(),
        creation_time,
        TTL_MIN,
    );
    let personal_msg = PersonalMessage {
        message: message.into_bytes(),
    };
    let user_sig: MySoSignature = wallet
        .config
        .keystore
        .sign_secure(&params.sender, &personal_msg, Intent::personal_message())
        .await
        .map_err(|e| FastCryptoError::GeneralError(format!("sign certificate: {e}")))?;
    let signature = GenericSignature::Signature(user_sig);

    let sdk_ptb = ptb_to_sdk(&ptb)?;
    let request_message = signed_request(&sdk_ptb, &enc_key, &enc_verification_key);
    let request_signature: fastcrypto::ed25519::Ed25519Signature = session.sign(&request_message);
    let request_body = json!({
        "ptb": Base64::encode(bcs::to_bytes(&ptb).expect("ptb bcs")),
        "enc_key": enc_key,
        "enc_verification_key": enc_verification_key,
        "request_signature": request_signature,
        "certificate": {
            "user": params.sender,
            "session_vk": session.public(),
            "creation_time": creation_time,
            "ttl_min": TTL_MIN,
            "signature": signature,
            "mvr_name": null,
        }
    });

    let http = reqwest::Client::new();
    let url = format!("{}/v1/fetch_key", params.key_server_url.trim_end_matches('/'));
    let response = http
        .post(&url)
        .header("Client-Sdk-Type", "rust")
        .header("Client-Sdk-Version", "1.0.0")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_string(&request_body)
                .map_err(|e| FastCryptoError::GeneralError(e.to_string()))?,
        ))
        .send()
        .await
        .map_err(|e| FastCryptoError::GeneralError(format!("fetch_key HTTP: {e}")))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(FastCryptoError::GeneralError(format!(
            "fetch_key failed HTTP {status}: {body}"
        )));
    }

    let response_bytes = response
        .bytes()
        .await
        .map_err(|e| FastCryptoError::GeneralError(format!("read body: {e}")))?;
    let fetch_response: FetchKeyResponse = serde_json::from_slice(&response_bytes)
        .map_err(|e| FastCryptoError::GeneralError(format!("parse response: {e}")))?;

    let pk_bytes = Hex::decode(params.server_public_key_hex.trim_start_matches("0x"))
        .map_err(|e| FastCryptoError::GeneralError(format!("server pk: {e}")))?;
    let server_pk = IBEPublicKey::from_byte_array(
        &pk_bytes
            .try_into()
            .map_err(|_| FastCryptoError::GeneralError("invalid server pk length".into()))?,
    )?;

    let server_oid = params.key_server_object_id;
    let mut server_pk_map = HashMap::new();
    server_pk_map.insert(server_oid, server_pk);

    let mydata_responses = [(server_oid, fetch_response)];
    let cached = decrypt_mydata_responses(&enc_secret, &mydata_responses, &server_pk_map)?;

    let enc_bytes = Hex::decode(params.encrypted_object_hex.trim_start_matches("0x"))
        .map_err(|e| FastCryptoError::GeneralError(format!("encrypted object: {e}")))?;
    let encrypted_object: EncryptedObject = bcs::from_bytes(&enc_bytes)
        .map_err(|e| FastCryptoError::GeneralError(format!("parse EncryptedObject: {e}")))?;

    mydata_sdk::mydata_decrypt_object(&encrypted_object, &cached, &server_pk_map)
}

fn to_types_oid(id: ObjectID) -> TypesObjectID {
    TypesObjectID::new(id.into_inner())
}

fn ptb_to_sdk(ptb: &ProgrammableTransaction) -> FastCryptoResult<SdkProgrammableTransaction> {
    bcs::from_bytes(&bcs::to_bytes(ptb).map_err(|e| ptb_err(e))?)
        .map_err(|e| ptb_err(e))
}

async fn build_profile_subscription_policy_ptb(
    client: &myso_sdk::MySoClient,
    package_id: TypesObjectID,
    encryption_id: Vec<u8>,
    memory_config_id: TypesObjectID,
    mydata_id: TypesObjectID,
    memory_account_id: TypesObjectID,
    service_id: TypesObjectID,
    subscription_id: TypesObjectID,
    clock_id: TypesObjectID,
    block_list_registry_id: TypesObjectID,
) -> FastCryptoResult<ProgrammableTransaction> {
    let mut builder = ProgrammableTransactionBuilder::new();
    let id_arg = builder.pure(encryption_id).map_err(|e| ptb_err(e))?;
    let post_service_id_arg = builder.pure(service_id).map_err(|e| ptb_err(e))?;
    let post_linked_mydata_id_arg = builder.pure(mydata_id).map_err(|e| ptb_err(e))?;
    // The linked post has no tier requirement in this policy; pass Option::none.
    let post_min_tier_level_arg = builder.pure(None::<u64>).map_err(|e| ptb_err(e))?;

    let memory_config = shared_object_arg(client, memory_config_id, false).await?;
    let mydata = shared_object_arg(client, mydata_id, false).await?;
    let memory_account = shared_object_arg(client, memory_account_id, false).await?;
    let service = shared_object_arg(client, service_id, false).await?;
    let subscription = owned_object_arg(client, subscription_id).await?;
    let clock = shared_object_arg(client, clock_id, false).await?;
    let block_list_registry =
        shared_object_arg(client, block_list_registry_id, false).await?;

    let memory_config_arg = builder.obj(memory_config).map_err(|e| ptb_err(e))?;
    let mydata_arg = builder.obj(mydata).map_err(|e| ptb_err(e))?;
    let memory_account_arg = builder.obj(memory_account).map_err(|e| ptb_err(e))?;
    let service_arg = builder.obj(service).map_err(|e| ptb_err(e))?;
    let subscription_arg = builder.obj(subscription).map_err(|e| ptb_err(e))?;
    let clock_arg = builder.obj(clock).map_err(|e| ptb_err(e))?;
    let block_list_registry_arg = builder
        .obj(block_list_registry)
        .map_err(|e| ptb_err(e))?;

    builder.programmable_move_call(
        package_id,
        Identifier::new("mydata").map_err(|e| ptb_err(e.to_string()))?,
        Identifier::new("mydata_approve_profile_subscription")
            .map_err(|e| ptb_err(e.to_string()))?,
        vec![],
        vec![
            id_arg,
            block_list_registry_arg,
            post_service_id_arg,
            post_linked_mydata_id_arg,
            post_min_tier_level_arg,
            memory_config_arg,
            mydata_arg,
            memory_account_arg,
            service_arg,
            subscription_arg,
            clock_arg,
        ],
    );

    Ok(builder.finish())
}

async fn shared_object_arg(
    client: &myso_sdk::MySoClient,
    id: TypesObjectID,
    mutable: bool,
) -> FastCryptoResult<ObjectArg> {
    let resp = client
        .read_api()
        .get_object_with_options(id, myso_sdk::rpc_types::MySoObjectDataOptions::full_content())
        .await
        .map_err(|e| FastCryptoError::GeneralError(format!("get_object {id}: {e}")))?;
    let data = resp
        .data
        .ok_or_else(|| FastCryptoError::GeneralError(format!("missing object {id}")))?;
    let owner = data
        .owner
        .ok_or_else(|| FastCryptoError::GeneralError(format!("no owner {id}")))?;
    let initial_shared_version = match owner {
        Owner::Shared {
            initial_shared_version: version,
        } => version,
        _ => {
            return Err(FastCryptoError::GeneralError(format!(
                "{id} is not a shared object"
            )));
        }
    };
    Ok(ObjectArg::SharedObject {
        id,
        initial_shared_version: initial_shared_version.into(),
        mutability: if mutable {
            SharedObjectMutability::Mutable
        } else {
            SharedObjectMutability::Immutable
        },
    })
}

async fn owned_object_arg(
    client: &myso_sdk::MySoClient,
    id: TypesObjectID,
) -> FastCryptoResult<ObjectArg> {
    let resp = client
        .read_api()
        .get_object_with_options(id, myso_sdk::rpc_types::MySoObjectDataOptions::full_content())
        .await
        .map_err(|e| FastCryptoError::GeneralError(format!("get_object {id}: {e}")))?;
    let data = resp
        .data
        .ok_or_else(|| FastCryptoError::GeneralError(format!("missing object {id}")))?;
    let digest = data
        .digest
        .try_into()
        .map_err(|_| FastCryptoError::GeneralError("digest parse".into()))?;
    Ok(ObjectArg::ImmOrOwnedObject((id, data.version, digest)))
}

fn load_wallet(
    client_config: Option<&std::path::Path>,
    active_address: Option<MySoAddress>,
) -> FastCryptoResult<WalletContext> {
    let config_path = client_config
        .map(PathBuf::from)
        .unwrap_or_else(default_client_config_path);
    let mut wallet = WalletContext::new(&config_path)
        .map_err(|e| FastCryptoError::GeneralError(format!("wallet: {e}")))?;
    if let Some(addr) = active_address {
        wallet.config.active_address = Some(addr);
    }
    Ok(wallet)
}

fn default_client_config_path() -> PathBuf {
    std::env::var("MYSO_CLIENT_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".myso")
                .join("myso_config")
                .join("client.yaml")
        })
}

fn ptb_err<E: std::fmt::Display>(e: E) -> FastCryptoError {
    FastCryptoError::GeneralError(format!("PTB: {e}"))
}

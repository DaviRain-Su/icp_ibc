use crate::constants::CYCLES_NUMBER;
use crate::Error;
use crate::Network;
use ic_cdk::export::{
    candid::CandidType,
    serde::{Deserialize, Serialize},
    Principal,
};
use ic_cdk::{query, update};
use k256::ecdsa::signature::Verifier;
use sha2::Digest;
use std::convert::TryFrom;
use std::str::FromStr;

#[derive(CandidType, Serialize, Debug)]
pub struct PublicKeyReply {
    pub public_key: Vec<u8>,
}

impl From<Vec<u8>> for PublicKeyReply {
    fn from(public_key: Vec<u8>) -> Self {
        Self { public_key }
    }
}

#[derive(CandidType, Serialize, Debug)]
pub struct SignatureReply {
    pub signature: Vec<u8>,
}

impl From<Vec<u8>> for SignatureReply {
    fn from(signature: Vec<u8>) -> Self {
        Self { signature }
    }
}

#[derive(CandidType, Serialize, Debug)]
struct SignatureVerificationReply {
    pub is_signature_valid: bool,
}

impl From<bool> for SignatureVerificationReply {
    fn from(is_signature_valid: bool) -> Self {
        Self { is_signature_valid }
    }
}

type CanisterId = Principal;

#[derive(CandidType, Serialize, Debug)]
struct ECDSAPublicKey {
    pub canister_id: Option<CanisterId>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: EcdsaKeyId,
}

#[derive(CandidType, Deserialize, Debug)]
struct ECDSAPublicKeyReply {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

#[derive(CandidType, Serialize, Debug)]
struct SignWithECDSA {
    pub message_hash: Vec<u8>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: EcdsaKeyId,
}

#[derive(CandidType, Deserialize, Debug)]
struct SignWithECDSAReply {
    pub signature: Vec<u8>,
}

#[derive(CandidType, Serialize, Debug, Clone)]
pub struct EcdsaKeyId {
    pub curve: EcdsaCurve,
    pub name: String,
}

#[derive(CandidType, Serialize, Debug, Clone)]
pub enum EcdsaCurve {
    #[serde(rename = "secp256k1")]
    Secp256k1,
}

#[update]
pub async fn public_key(network: Network) -> Result<PublicKeyReply, Error> {
    let request = ECDSAPublicKey {
        canister_id: None,
        derivation_path: vec![],
        key_id: network.key_id(),
    };

    let (res,): (ECDSAPublicKeyReply,) =
        ic_cdk::call(mgmt_canister_id(), "ecdsa_public_key", (request,))
            .await
            .map_err(|(_, e)| {
                Error::CustomError(format!(
                    "ecdsa_public_key failed Error:({e}) \n {}",
                    std::panic::Location::caller()
                ))
            })?;

    Ok(res.public_key.into())
}

#[update]
pub async fn sign(network: Network, message: Vec<u8>) -> Result<SignatureReply, Error> {
    let request = SignWithECDSA {
        message_hash: sha256(&message).to_vec(),
        derivation_path: vec![],
        key_id: network.key_id(),
    };

    let (response,): (SignWithECDSAReply,) = ic_cdk::api::call::call_with_payment(
        mgmt_canister_id(),
        "sign_with_ecdsa",
        (request,),
        CYCLES_NUMBER,
    )
    .await
    .map_err(|(_, e)| {
        Error::CustomError(format!(
            "sign_with_ecdsa failed Error({e}) \n {}",
            std::panic::Location::caller()
        ))
    })?;

    Ok(response.signature.into())
}

#[query]
async fn verify(
    signature_hex: String,
    message: String,
    public_key_hex: String,
) -> Result<SignatureVerificationReply, Error> {
    let signature_bytes = hex::decode(signature_hex).map_err(|e| {
        Error::CustomError(format!(
            "failed to hex-decode signature: Error({e:?}) \n {}",
            std::panic::Location::caller()
        ))
    })?;
    let pubkey_bytes = hex::decode(public_key_hex).map_err(|e| {
        Error::CustomError(format!(
            "failed to hex-decode public key: Error({e:?}) \n {}",
            std::panic::Location::caller()
        ))
    })?;

    let signature = k256::ecdsa::Signature::try_from(signature_bytes.as_slice()).map_err(|e| {
        Error::CustomError(format!(
            "failed to deserialize signature: Error({e:?}) \n {}",
            std::panic::Location::caller()
        ))
    })?;

    let is_signature_valid = k256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey_bytes)
        .map_err(|e| {
            Error::CustomError(format!(
                "failed to deserialize sec1 encoding into public key: Error({e:?}) \n {}",
                std::panic::Location::caller()
            ))
        })?
        .verify(message.as_bytes(), &signature)
        .is_ok();

    Ok(is_signature_valid.into())
}

fn mgmt_canister_id() -> CanisterId {
    CanisterId::from_str("aaaaa-aa").expect("build CanisterId failed")
}

fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

pub enum EcdsaKeyIds {
    #[allow(unused)]
    TestKeyLocalDevelopment,
    #[allow(unused)]
    TestKey1,
    #[allow(unused)]
    ProductionKey1,
}

impl EcdsaKeyIds {
    pub fn to_key_id(&self) -> EcdsaKeyId {
        EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: match self {
                Self::TestKeyLocalDevelopment => "dfx_test_key",
                Self::TestKey1 => "test_key_1",
                Self::ProductionKey1 => "key_1",
            }
            .to_string(),
        }
    }
}

// In the following, we register a custom getrandom implementation because
// otherwise getrandom (which is a dependency of k256) fails to compile.
// This is necessary because getrandom by default fails to compile for the
// wasm32-unknown-unknown target (which is required for deploying a canister).
// Our custom implementation always fails, which is sufficient here because
// we only use the k256 crate for verifying secp256k1 signatures, and such
// signature verification does not require any randomness.
getrandom::register_custom_getrandom!(always_fail);
pub fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

// #![allow(unused_imports)]
extern crate alloc;

mod auth;
mod constants;
mod errors;
mod ibc_impl;
mod signer;
mod util;

use crate::errors::Error;
use auth::{is_authorized, is_owner};
use candid::types::principal::Principal;
use ibc::clients::ics07_tendermint::client_state::test_util::ClientStateConfig as TmClientStateConfig;
use ibc::clients::ics07_tendermint::client_state::{
    ClientState as TmClientState, TENDERMINT_CLIENT_STATE_TYPE_URL,
};
use ibc::clients::ics07_tendermint::consensus_state::{
    ConsensusState as TmConsensusState, TENDERMINT_CONSENSUS_STATE_TYPE_URL,
};
use ibc::core::events::IbcEvent;
use ibc::core::ics02_client::client_state::ClientState;
use ibc::core::ics02_client::client_type::ClientType;
use ibc::core::ics02_client::consensus_state::ConsensusState;
use ibc::core::ics02_client::error::ClientError;
use ibc::core::ics03_connection::connection::ConnectionEnd;
use ibc::core::ics03_connection::error::ConnectionError;
use ibc::core::ics04_channel::acknowledgement::Acknowledgement;
use ibc::core::ics04_channel::channel::ChannelEnd;
use ibc::core::ics04_channel::commitment::{AcknowledgementCommitment, PacketCommitment};
use ibc::core::ics04_channel::error::{ChannelError, PacketError};
use ibc::core::ics04_channel::packet::{Receipt, Sequence};
use ibc::core::ics04_channel::timeout::TimeoutHeight;
use ibc::core::ics23_commitment::commitment::CommitmentPrefix;
use ibc::core::ics24_host::identifier::{ChainId, ChannelId, ClientId, ConnectionId, PortId};
use ibc::core::ics24_host::path::{
    AckPath, ChannelEndPath, ClientConnectionPath, ClientConsensusStatePath, CommitmentPath,
    ConnectionPath, ReceiptPath, SeqAckPath, SeqRecvPath, SeqSendPath,
};
use ibc::core::router::Router;
use ibc::core::timestamp::Timestamp;
use ibc::core::Msg;
use ibc::core::{dispatch, ContextError, ExecutionContext, MsgEnvelope, ValidationContext};
use ibc::mock::client_state::{client_type as mock_client_type, MockClientState};
use ibc::mock::client_state::{MOCK_CLIENT_STATE_TYPE_URL, MOCK_CLIENT_TYPE};
use ibc::mock::consensus_state::MockConsensusState;
use ibc::mock::consensus_state::MOCK_CONSENSUS_STATE_TYPE_URL;
use ibc::mock::header::MockHeader;
use ibc::mock::host::{HostBlock, HostType};
use ibc::mock::ics18_relayer::context::RelayerContext;
use ibc::mock::ics18_relayer::error::RelayerError;
use ibc::Height;
use ibc::Signer;

use ibc_impl::context::MockContext;
use ibc_proto::protobuf::Protobuf;
use log::info;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::cell::RefCell;
use std::collections::HashSet;
use util::{Network, Ts};

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

#[derive(Debug, Deserialize, Serialize)]
struct State {
    network: Network,
    ctx: MockContext,
    latest_sequence: u64,
    is_frozen: bool,
    diversifier: String,
    ts: Ts,
    owner: Option<Principal>,
    relayers: HashSet<Principal>,
}

impl Default for State {
    fn default() -> Self {
        State {
            network: Network::Local,
            ctx: MockContext::default(),
            latest_sequence: 1,
            is_frozen: false,
            diversifier: "oct".to_string(),
            ts: Ts {
                timestamp: 0,
                height: Height::min(0),
            },
            owner: None,
            relayers: HashSet::default(),
        }
    }
}

#[ic_cdk::init]
fn init(network: Network) {
    ic_cdk::setup();
    util::init_log();
    info!("network: {network:?}");
    // init authorized user id
    let caller = ic_cdk::api::caller();
    info!("caller: {:?}", caller.to_text());
    STATE.set(State {
        owner: Some(caller),
        network,
        ..Default::default()
    });
}

#[ic_cdk::pre_upgrade(guard = "is_owner")]
fn pre_upgrade() {
    let state = STATE.take();
    let serialized_state = serde_json::to_string(&state).expect("serde failed to serialize state");
    info!("serialized_state: {serialized_state:?}");

    ic_cdk::storage::stable_save((serialized_state,)).expect("failed to save stable state");
}

#[ic_cdk::post_upgrade(guard = "is_owner")]
fn post_upgrade() {
    util::init_log();
    let (serialized_state,): (String,) =
        ic_cdk::storage::stable_restore().expect("failed to restore stable state");

    let state: State =
        serde_json::from_str(&serialized_state).expect("serde failed to deserialize");

    STATE.replace(state);
}

#[ic_cdk::update(guard = "is_owner")]
async fn update_commitment_prefix(prefix: String) -> Result<(), Error> {
    let prefix = CommitmentPrefix::try_from(prefix.into_bytes())
        .map_err(|e| Error::CustomError(e.to_string()))?;
    info!("update commitment_prefix: {prefix:?}");
    STATE.with_borrow_mut(|state| {
        *state.ctx.commitment_prefix_mut() = prefix;
    });
    Ok(())
}

#[ic_cdk::update(guard = "is_authorized")]
async fn deliver(msg: Vec<u8>) -> Result<(), Error> {
    todo!()
}

fn compute_packet_commitment(
    packet_data: &[u8],
    timeout_height: &TimeoutHeight,
    timeout_timestamp: &Timestamp,
) -> PacketCommitment {
    let mut hash_input = timeout_timestamp.nanoseconds().to_be_bytes().to_vec();

    let revision_number = timeout_height.commitment_revision_number().to_be_bytes();
    hash_input.append(&mut revision_number.to_vec());

    let revision_height = timeout_height.commitment_revision_height().to_be_bytes();
    hash_input.append(&mut revision_height.to_vec());

    let packet_data_hash = hash(packet_data);
    hash_input.append(&mut packet_data_hash.to_vec());

    hash(&hash_input).into()
}

fn compute_ack_commitment(ack: &Acknowledgement) -> AcknowledgementCommitment {
    hash(ack.as_ref()).into()
}

fn hash(data: impl AsRef<[u8]>) -> Vec<u8> {
    sha2::Sha256::digest(&data).to_vec()
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum QueryHeight {
    Latest,
    Specific(Height),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryClientStateRequest {
    pub client_id: ClientId,
    pub height: QueryHeight,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryConsensusStateRequest {
    pub client_id: ClientId,
    pub consensus_height: Height,
    pub query_height: QueryHeight,
}

#[ic_cdk::query]
fn query_client_state(args: Vec<u8>) -> Result<Vec<u8>, Error> {
    let QueryClientStateRequest { client_id, .. } = serde_json::from_slice(&args).map_err(|e| {
        Error::CustomError(format!(
            "serde failed to deserialize: Error({e}) \n {}",
            std::panic::Location::caller()
        ))
    })?;

    STATE
        .with(|s| {
            s.borrow()
                .ctx
                .client_state(&client_id)
                .map(|cs| cs.encode_vec())
        })
        .map_err(|e| Error::ClientStateNotFound(e.to_string()))
}

#[ic_cdk::query]
fn query_consensus_state(args: Vec<u8>) -> Result<Vec<u8>, Error> {
    let QueryConsensusStateRequest {
        client_id,
        consensus_height,
        ..
    } = serde_json::from_slice(&args).map_err(|e| {
        Error::CustomError(format!(
            "serde failed to deserialize: Error({e}) \n {}",
            std::panic::Location::caller()
        ))
    })?;
    let path = ClientConsensusStatePath::new(&client_id, &consensus_height);

    STATE
        .with(|s| {
            s.borrow()
                .ctx
                .consensus_state(&path)
                .map(|cs| cs.encode_vec())
        })
        .map_err(|e| Error::ConsensusStateNotFound(e.to_string()))
}

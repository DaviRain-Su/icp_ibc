//! Implementation of a global context mock. Used in testing handlers of all IBC modules.

mod clients;

use alloc::collections::btree_map::BTreeMap;
use alloc::sync::Arc;
use core::fmt::Debug;
use core::time::Duration;
use derive_more::{From, TryInto};
use ibc::clients::ics07_tendermint::client_state::{
    ClientState as TmClientState, TENDERMINT_CLIENT_STATE_TYPE_URL,
};
use ibc::clients::ics07_tendermint::consensus_state::{
    ConsensusState as TmConsensusState, TENDERMINT_CONSENSUS_STATE_TYPE_URL,
};
use ibc::core::events::IbcEvent;
use ibc::core::ics02_client::client_state::ClientState;
use ibc::core::ics02_client::consensus_state::ConsensusState;
use ibc::core::ics02_client::error::ClientError;
use ibc::core::ics03_connection::connection::ConnectionEnd;
use ibc::core::ics03_connection::error::ConnectionError;
use ibc::core::ics04_channel::channel::ChannelEnd;
use ibc::core::ics04_channel::commitment::{AcknowledgementCommitment, PacketCommitment};
use ibc::core::ics04_channel::error::{ChannelError, PacketError};
use ibc::core::ics04_channel::packet::{Receipt, Sequence};
use ibc::core::ics23_commitment::commitment::CommitmentPrefix;
use ibc::core::ics24_host::identifier::{ChainId, ChannelId, ClientId, ConnectionId, PortId};
use ibc::core::ics24_host::path::{
    AckPath, ChannelEndPath, ClientConnectionPath, ClientConsensusStatePath, CommitmentPath,
    ConnectionPath, ReceiptPath, SeqAckPath, SeqRecvPath, SeqSendPath,
};
use ibc::core::timestamp::Timestamp;
use ibc::core::{ContextError, ExecutionContext, ValidationContext};
use ibc::Height;
use ibc::Signer;
use ibc_proto::google::protobuf::Any;
use ibc_proto::protobuf::Protobuf;
use parking_lot::Mutex;
// use tendermint_testgen::Validator as TestgenValidator;
// use typed_builder::TypedBuilder;

// pub const DEFAULT_BLOCK_TIME_SECS: u64 = 3;
// pub const TENDERMINT_CLIENT_TYPE: &str = "07-tendermint";

#[derive(Debug, Clone, From, PartialEq, ClientState)]
#[generics(ClientValidationContext = MockContext,
           ClientExecutionContext = MockContext)
]
pub enum AnyClientState {
    Tendermint(TmClientState),
}

impl Protobuf<Any> for AnyClientState {}

impl TryFrom<Any> for AnyClientState {
    type Error = ClientError;

    fn try_from(raw: Any) -> Result<Self, Self::Error> {
        if raw.type_url == TENDERMINT_CLIENT_STATE_TYPE_URL {
            TmClientState::try_from(raw).map(Into::into)
        } else {
            Err(ClientError::Other {
                description: "failed to deserialize message".to_string(),
            })
        }
    }
}

impl From<AnyClientState> for Any {
    fn from(host_client_state: AnyClientState) -> Self {
        match host_client_state {
            AnyClientState::Tendermint(cs) => cs.into(),
        }
    }
}

#[derive(Debug, Clone, From, TryInto, PartialEq, ConsensusState)]
pub enum AnyConsensusState {
    Tendermint(TmConsensusState),
}

impl Protobuf<Any> for AnyConsensusState {}

impl TryFrom<Any> for AnyConsensusState {
    type Error = ClientError;

    fn try_from(raw: Any) -> Result<Self, Self::Error> {
        if raw.type_url == TENDERMINT_CONSENSUS_STATE_TYPE_URL {
            TmConsensusState::try_from(raw).map(Into::into)
        } else {
            Err(ClientError::Other {
                description: "failed to deserialize message".to_string(),
            })
        }
    }
}

impl From<AnyConsensusState> for Any {
    fn from(host_consensus_state: AnyConsensusState) -> Self {
        match host_consensus_state {
            AnyConsensusState::Tendermint(cs) => cs.into(),
        }
    }
}

/// A mock of an IBC client record as it is stored in a mock context.
/// For testing ICS02 handlers mostly, cf. `MockClientContext`.
#[derive(Clone, Debug)]
pub struct MockClientRecord {
    /// The client state (representing only the latest height at the moment).
    pub client_state: Option<AnyClientState>,

    /// Mapping of heights to consensus states for this client.
    pub consensus_states: BTreeMap<Height, AnyConsensusState>,
}

/// An object that stores all IBC related data.
#[derive(Clone, Debug, Default)]
pub struct MockIbcStore {
    /// The set of all clients, indexed by their id.
    pub clients: BTreeMap<ClientId, MockClientRecord>,

    /// Tracks the processed time for clients header updates
    pub client_processed_times: BTreeMap<(ClientId, Height), Timestamp>,

    /// Tracks the processed height for the clients
    pub client_processed_heights: BTreeMap<(ClientId, Height), Height>,

    /// Counter for the client identifiers, necessary for `increase_client_counter` and the
    /// `client_counter` methods.
    pub client_ids_counter: u64,

    /// Association between client ids and connection ids.
    pub client_connections: BTreeMap<ClientId, ConnectionId>,

    /// All the connections in the store.
    pub connections: BTreeMap<ConnectionId, ConnectionEnd>,

    /// Counter for connection identifiers (see `increase_connection_counter`).
    pub connection_ids_counter: u64,

    /// Association between connection ids and channel ids.
    pub connection_channels: BTreeMap<ConnectionId, Vec<(PortId, ChannelId)>>,

    /// Counter for channel identifiers (see `increase_channel_counter`).
    pub channel_ids_counter: u64,

    /// All the channels in the store. TODO Make new key PortId X ChannelId
    pub channels: PortChannelIdMap<ChannelEnd>,

    /// Tracks the sequence number for the next packet to be sent.
    pub next_sequence_send: PortChannelIdMap<Sequence>,

    /// Tracks the sequence number for the next packet to be received.
    pub next_sequence_recv: PortChannelIdMap<Sequence>,

    /// Tracks the sequence number for the next packet to be acknowledged.
    pub next_sequence_ack: PortChannelIdMap<Sequence>,

    pub packet_acknowledgement: PortChannelIdMap<BTreeMap<Sequence, AcknowledgementCommitment>>,

    /// Constant-size commitments to packets data fields
    pub packet_commitment: PortChannelIdMap<BTreeMap<Sequence, PacketCommitment>>,

    // Used by unordered channel
    pub packet_receipt: PortChannelIdMap<BTreeMap<Sequence, Receipt>>,
}

/// A context implementing the dependencies necessary for testing any IBC module.
#[derive(Debug)]
pub struct MockContext {
    /// The type of host chain underlying this mock context.
    // host_chain_type: HostType,

    /// Host chain identifier.
    host_chain_id: ChainId,

    /// Maximum size for the history of the host chain. Any block older than this is pruned.
    max_history_size: u64,

    /// The chain of blocks underlying this context. A vector of size up to `max_history_size`
    /// blocks, ascending order by their height (latest block is on the last position).
    // history: Vec<HostBlock>,

    /// Average time duration between blocks
    block_time: Duration,

    /// An object that stores all IBC related data.
    pub ibc_store: Arc<Mutex<MockIbcStore>>,

    pub events: Vec<IbcEvent>,

    pub logs: Vec<String>,
}

// #[derive(Debug)]
// pub struct MockContextConfig {
//     host_id: ChainId,
//     block_time: Duration,
//     // may panic if validator_set_history size is less than max_history_size + 1
//     max_history_size: u64,
//     validator_set_history: Option<Vec<Vec<TestgenValidator>>>,
//     latest_height: Height,
//     latest_timestamp: Timestamp,
// }

// #[derive(Debug, TypedBuilder)]
// pub struct MockClientConfig {
//     client_chain_id: ChainId,
//     client_id: ClientId,
//     client_type: ClientType,
//     client_state_height: Height,
//     #[builder(default)]
//     consensus_state_heights: Vec<Height>,
//     #[builder(default = Timestamp::now())]
//     latest_timestamp: Timestamp,

//     #[builder(default = Duration::from_secs(64000))]
//     pub trusting_period: Duration,
//     #[builder(default = Duration::from_millis(3000))]
//     max_clock_drift: Duration,
// }

/// A manual clone impl is provided because the tests are oblivious to the fact that the `ibc_store`
/// is a shared ptr.
impl Clone for MockContext {
    fn clone(&self) -> Self {
        let ibc_store = {
            let ibc_store = self.ibc_store.lock().clone();
            Arc::new(Mutex::new(ibc_store))
        };

        Self {
            // host_chain_type: self.host_chain_type,
            host_chain_id: self.host_chain_id.clone(),
            max_history_size: self.max_history_size,
            // history: self.history.clone(),
            block_time: self.block_time,
            ibc_store,
            events: self.events.clone(),
            logs: self.logs.clone(),
        }
    }
}

type PortChannelIdMap<V> = BTreeMap<PortId, BTreeMap<ChannelId, V>>;

impl ValidationContext for MockContext {
    type V = Self;
    type E = Self;
    type AnyConsensusState = AnyConsensusState;
    type AnyClientState = AnyClientState;

    fn client_state(&self, client_id: &ClientId) -> Result<Self::AnyClientState, ContextError> {
        match self.ibc_store.lock().clients.get(client_id) {
            Some(client_record) => {
                client_record
                    .client_state
                    .clone()
                    .ok_or_else(|| ClientError::ClientStateNotFound {
                        client_id: client_id.clone(),
                    })
            }
            None => Err(ClientError::ClientStateNotFound {
                client_id: client_id.clone(),
            }),
        }
        .map_err(ContextError::ClientError)
    }

    fn decode_client_state(&self, client_state: Any) -> Result<Self::AnyClientState, ContextError> {
        if let Ok(client_state) = TmClientState::try_from(client_state.clone()) {
            client_state.validate().map_err(ClientError::from)?;
            Ok(client_state.into())
        } else {
            Err(ClientError::UnknownClientStateType {
                client_state_type: client_state.type_url,
            })
        }
        .map_err(ContextError::ClientError)
    }

    fn consensus_state(
        &self,
        client_cons_state_path: &ClientConsensusStatePath,
    ) -> Result<AnyConsensusState, ContextError> {
        let client_id = &client_cons_state_path.client_id;
        let height = Height::new(client_cons_state_path.epoch, client_cons_state_path.height)?;
        match self.ibc_store.lock().clients.get(client_id) {
            Some(client_record) => match client_record.consensus_states.get(&height) {
                Some(consensus_state) => Ok(consensus_state.clone()),
                None => Err(ClientError::ConsensusStateNotFound {
                    client_id: client_id.clone(),
                    height,
                }),
            },
            None => Err(ClientError::ConsensusStateNotFound {
                client_id: client_id.clone(),
                height,
            }),
        }
        .map_err(ContextError::ClientError)
    }

    fn host_height(&self) -> Result<Height, ContextError> {
        todo!()
    }

    fn host_timestamp(&self) -> Result<Timestamp, ContextError> {
        todo!()
    }

    fn host_consensus_state(&self, _height: &Height) -> Result<AnyConsensusState, ContextError> {
        todo!()
    }

    fn client_counter(&self) -> Result<u64, ContextError> {
        Ok(self.ibc_store.lock().client_ids_counter)
    }

    fn connection_end(&self, cid: &ConnectionId) -> Result<ConnectionEnd, ContextError> {
        match self.ibc_store.lock().connections.get(cid) {
            Some(connection_end) => Ok(connection_end.clone()),
            None => Err(ConnectionError::ConnectionNotFound {
                connection_id: cid.clone(),
            }),
        }
        .map_err(ContextError::ConnectionError)
    }

    fn validate_self_client(
        &self,
        _client_state_of_host_on_counterparty: Any,
    ) -> Result<(), ContextError> {
        Ok(())
    }

    fn commitment_prefix(&self) -> CommitmentPrefix {
        CommitmentPrefix::try_from(b"mock".to_vec()).expect("Never fails")
    }

    fn connection_counter(&self) -> Result<u64, ContextError> {
        Ok(self.ibc_store.lock().connection_ids_counter)
    }

    fn channel_end(&self, chan_end_path: &ChannelEndPath) -> Result<ChannelEnd, ContextError> {
        let port_id = &chan_end_path.0;
        let channel_id = &chan_end_path.1;

        match self
            .ibc_store
            .lock()
            .channels
            .get(port_id)
            .and_then(|map| map.get(channel_id))
        {
            Some(channel_end) => Ok(channel_end.clone()),
            None => Err(ChannelError::ChannelNotFound {
                port_id: port_id.clone(),
                channel_id: channel_id.clone(),
            }),
        }
        .map_err(ContextError::ChannelError)
    }

    fn get_next_sequence_send(
        &self,
        seq_send_path: &SeqSendPath,
    ) -> Result<Sequence, ContextError> {
        let port_id = &seq_send_path.0;
        let channel_id = &seq_send_path.1;

        match self
            .ibc_store
            .lock()
            .next_sequence_send
            .get(port_id)
            .and_then(|map| map.get(channel_id))
        {
            Some(sequence) => Ok(*sequence),
            None => Err(PacketError::MissingNextSendSeq {
                port_id: port_id.clone(),
                channel_id: channel_id.clone(),
            }),
        }
        .map_err(ContextError::PacketError)
    }

    fn get_next_sequence_recv(
        &self,
        seq_recv_path: &SeqRecvPath,
    ) -> Result<Sequence, ContextError> {
        let port_id = &seq_recv_path.0;
        let channel_id = &seq_recv_path.1;

        match self
            .ibc_store
            .lock()
            .next_sequence_recv
            .get(port_id)
            .and_then(|map| map.get(channel_id))
        {
            Some(sequence) => Ok(*sequence),
            None => Err(PacketError::MissingNextRecvSeq {
                port_id: port_id.clone(),
                channel_id: channel_id.clone(),
            }),
        }
        .map_err(ContextError::PacketError)
    }

    fn get_next_sequence_ack(&self, seq_ack_path: &SeqAckPath) -> Result<Sequence, ContextError> {
        let port_id = &seq_ack_path.0;
        let channel_id = &seq_ack_path.1;

        match self
            .ibc_store
            .lock()
            .next_sequence_ack
            .get(port_id)
            .and_then(|map| map.get(channel_id))
        {
            Some(sequence) => Ok(*sequence),
            None => Err(PacketError::MissingNextAckSeq {
                port_id: port_id.clone(),
                channel_id: channel_id.clone(),
            }),
        }
        .map_err(ContextError::PacketError)
    }

    fn get_packet_commitment(
        &self,
        commitment_path: &CommitmentPath,
    ) -> Result<PacketCommitment, ContextError> {
        let port_id = &commitment_path.port_id;
        let channel_id = &commitment_path.channel_id;
        let seq = &commitment_path.sequence;

        match self
            .ibc_store
            .lock()
            .packet_commitment
            .get(port_id)
            .and_then(|map| map.get(channel_id))
            .and_then(|map| map.get(seq))
        {
            Some(commitment) => Ok(commitment.clone()),
            None => Err(PacketError::PacketCommitmentNotFound { sequence: *seq }),
        }
        .map_err(ContextError::PacketError)
    }

    fn get_packet_receipt(&self, receipt_path: &ReceiptPath) -> Result<Receipt, ContextError> {
        let port_id = &receipt_path.port_id;
        let channel_id = &receipt_path.channel_id;
        let seq = &receipt_path.sequence;

        match self
            .ibc_store
            .lock()
            .packet_receipt
            .get(port_id)
            .and_then(|map| map.get(channel_id))
            .and_then(|map| map.get(seq))
        {
            Some(receipt) => Ok(receipt.clone()),
            None => Err(PacketError::PacketReceiptNotFound { sequence: *seq }),
        }
        .map_err(ContextError::PacketError)
    }

    fn get_packet_acknowledgement(
        &self,
        ack_path: &AckPath,
    ) -> Result<AcknowledgementCommitment, ContextError> {
        let port_id = &ack_path.port_id;
        let channel_id = &ack_path.channel_id;
        let seq = &ack_path.sequence;

        match self
            .ibc_store
            .lock()
            .packet_acknowledgement
            .get(port_id)
            .and_then(|map| map.get(channel_id))
            .and_then(|map| map.get(seq))
        {
            Some(ack) => Ok(ack.clone()),
            None => Err(PacketError::PacketAcknowledgementNotFound { sequence: *seq }),
        }
        .map_err(ContextError::PacketError)
    }

    fn channel_counter(&self) -> Result<u64, ContextError> {
        Ok(self.ibc_store.lock().channel_ids_counter)
    }

    fn max_expected_time_per_block(&self) -> Duration {
        self.block_time
    }

    fn validate_message_signer(&self, _signer: &Signer) -> Result<(), ContextError> {
        Ok(())
    }

    fn get_client_validation_context(&self) -> &Self::V {
        self
    }
}

impl ExecutionContext for MockContext {
    fn get_client_execution_context(&mut self) -> &mut Self::E {
        self
    }

    fn increase_client_counter(&mut self) -> Result<(), ContextError> {
        let mut ibc_store = self.ibc_store.lock();

        ibc_store.client_ids_counter = ibc_store
            .client_ids_counter
            .checked_add(1)
            .ok_or(ClientError::CounterOverflow)?;

        Ok(())
    }

    fn store_connection(
        &mut self,
        connection_path: &ConnectionPath,
        connection_end: ConnectionEnd,
    ) -> Result<(), ContextError> {
        let connection_id = connection_path.0.clone();
        self.ibc_store
            .lock()
            .connections
            .insert(connection_id, connection_end);
        Ok(())
    }

    fn store_connection_to_client(
        &mut self,
        client_connection_path: &ClientConnectionPath,
        conn_id: ConnectionId,
    ) -> Result<(), ContextError> {
        let client_id = client_connection_path.0.clone();
        self.ibc_store
            .lock()
            .client_connections
            .insert(client_id, conn_id);
        Ok(())
    }

    fn increase_connection_counter(&mut self) -> Result<(), ContextError> {
        let mut ibc_store = self.ibc_store.lock();

        ibc_store.connection_ids_counter = ibc_store
            .connection_ids_counter
            .checked_add(1)
            .ok_or(ClientError::CounterOverflow)?;

        Ok(())
    }

    fn store_packet_commitment(
        &mut self,
        commitment_path: &CommitmentPath,
        commitment: PacketCommitment,
    ) -> Result<(), ContextError> {
        self.ibc_store
            .lock()
            .packet_commitment
            .entry(commitment_path.port_id.clone())
            .or_default()
            .entry(commitment_path.channel_id.clone())
            .or_default()
            .insert(commitment_path.sequence, commitment);
        Ok(())
    }

    fn delete_packet_commitment(
        &mut self,
        commitment_path: &CommitmentPath,
    ) -> Result<(), ContextError> {
        self.ibc_store
            .lock()
            .packet_commitment
            .get_mut(&commitment_path.port_id)
            .and_then(|map| map.get_mut(&commitment_path.channel_id))
            .and_then(|map| map.remove(&commitment_path.sequence));
        Ok(())
    }

    fn store_packet_receipt(
        &mut self,
        path: &ReceiptPath,
        receipt: Receipt,
    ) -> Result<(), ContextError> {
        self.ibc_store
            .lock()
            .packet_receipt
            .entry(path.port_id.clone())
            .or_default()
            .entry(path.channel_id.clone())
            .or_default()
            .insert(path.sequence, receipt);
        Ok(())
    }

    fn store_packet_acknowledgement(
        &mut self,
        ack_path: &AckPath,
        ack_commitment: AcknowledgementCommitment,
    ) -> Result<(), ContextError> {
        let port_id = ack_path.port_id.clone();
        let channel_id = ack_path.channel_id.clone();
        let seq = ack_path.sequence;

        self.ibc_store
            .lock()
            .packet_acknowledgement
            .entry(port_id)
            .or_default()
            .entry(channel_id)
            .or_default()
            .insert(seq, ack_commitment);
        Ok(())
    }

    fn delete_packet_acknowledgement(&mut self, ack_path: &AckPath) -> Result<(), ContextError> {
        let port_id = ack_path.port_id.clone();
        let channel_id = ack_path.channel_id.clone();
        let sequence = ack_path.sequence;

        self.ibc_store
            .lock()
            .packet_acknowledgement
            .get_mut(&port_id)
            .and_then(|map| map.get_mut(&channel_id))
            .and_then(|map| map.remove(&sequence));
        Ok(())
    }

    fn store_channel(
        &mut self,
        channel_end_path: &ChannelEndPath,
        channel_end: ChannelEnd,
    ) -> Result<(), ContextError> {
        let port_id = channel_end_path.0.clone();
        let channel_id = channel_end_path.1.clone();

        self.ibc_store
            .lock()
            .channels
            .entry(port_id)
            .or_default()
            .insert(channel_id, channel_end);
        Ok(())
    }

    fn store_next_sequence_send(
        &mut self,
        seq_send_path: &SeqSendPath,
        seq: Sequence,
    ) -> Result<(), ContextError> {
        let port_id = seq_send_path.0.clone();
        let channel_id = seq_send_path.1.clone();

        self.ibc_store
            .lock()
            .next_sequence_send
            .entry(port_id)
            .or_default()
            .insert(channel_id, seq);
        Ok(())
    }

    fn store_next_sequence_recv(
        &mut self,
        seq_recv_path: &SeqRecvPath,
        seq: Sequence,
    ) -> Result<(), ContextError> {
        let port_id = seq_recv_path.0.clone();
        let channel_id = seq_recv_path.1.clone();

        self.ibc_store
            .lock()
            .next_sequence_recv
            .entry(port_id)
            .or_default()
            .insert(channel_id, seq);
        Ok(())
    }

    fn store_next_sequence_ack(
        &mut self,
        seq_ack_path: &SeqAckPath,
        seq: Sequence,
    ) -> Result<(), ContextError> {
        let port_id = seq_ack_path.0.clone();
        let channel_id = seq_ack_path.1.clone();

        self.ibc_store
            .lock()
            .next_sequence_ack
            .entry(port_id)
            .or_default()
            .insert(channel_id, seq);
        Ok(())
    }

    fn increase_channel_counter(&mut self) -> Result<(), ContextError> {
        let mut ibc_store = self.ibc_store.lock();

        ibc_store.channel_ids_counter = ibc_store
            .channel_ids_counter
            .checked_add(1)
            .ok_or(ClientError::CounterOverflow)?;

        Ok(())
    }

    fn emit_ibc_event(&mut self, event: IbcEvent) -> Result<(), ContextError> {
        self.events.push(event);
        Ok(())
    }

    fn log_message(&mut self, message: String) -> Result<(), ContextError> {
        self.logs.push(message);
        Ok(())
    }
}

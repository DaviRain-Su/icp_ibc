use crate::auth;
use crate::errors::Error;
use crate::signer::{EcdsaKeyId, EcdsaKeyIds};
use auth::is_owner;
use candid::CandidType;
use ibc::Height;
use ic_log::{LogSettings, LoggerConfig};
use log::{debug, info};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::fmt;
use std::marker::PhantomData;
use std::rc::Rc;
use std::str::FromStr;

thread_local! {
    static LOGGER_CONFIG: RefCell<Option<LoggerConfig>> = RefCell::new(None);
}

type ForceNotSendAndNotSync = PhantomData<Rc<()>>;

#[derive(CandidType, Clone, Copy, Deserialize, Debug, Eq, PartialEq, Serialize, Hash)]
pub enum Network {
    #[serde(rename = "local")]
    Local,
    #[serde(rename = "testnet")]
    Testnet,
    #[serde(rename = "mainnet")]
    Mainnet,
}

impl Network {
    pub fn key_id(&self) -> EcdsaKeyId {
        match self {
            Network::Local => EcdsaKeyIds::TestKeyLocalDevelopment.to_key_id(),
            Network::Testnet => EcdsaKeyIds::TestKey1.to_key_id(),
            Network::Mainnet => EcdsaKeyIds::ProductionKey1.to_key_id(),
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::Testnet => write!(f, "testnet"),
            Self::Mainnet => write!(f, "mainnet"),
        }
    }
}

impl FromStr for Network {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "regtest" => Ok(Network::Local),
            "testnet" => Ok(Network::Testnet),
            "mainnet" => Ok(Network::Mainnet),
            _ => Err(Error::CustomError("Bad network".to_string())),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Ts {
    pub timestamp: u64,
    pub height: Height,
}

#[derive(Debug, Default)]
/// Handles the runtime logger configuration
pub struct LoggerConfigService(ForceNotSendAndNotSync);

impl LoggerConfigService {
    pub fn init(&self, logger_config: LoggerConfig) {
        LOGGER_CONFIG.with_borrow_mut(|config| config.replace(logger_config));
    }

    /// Changes the logger filter at runtime
    pub fn set_logger_filter(&self, filter: &str) {
        LOGGER_CONFIG.with_borrow_mut(|config| match *config {
            Some(ref logger_config) => {
                logger_config.update_filters(filter);
            }
            None => panic!("LoggerConfig not initialized"),
        });
    }
}

pub fn init_log() {
    let settings = LogSettings {
        in_memory_records: Some(256),
        log_filter: Some("info".to_string()),
        enable_console: true,
    };
    match ic_log::init_log(&settings) {
        Ok(logger_config) => LoggerConfigService::default().init(logger_config),
        Err(err) => {
            ic_cdk::println!(
                "error configuring the logger. Err({err:?}) \n {}",
                std::panic::Location::caller()
            );
        }
    }
    info!("Logger initialized");
}

#[ic_cdk::query]
pub fn get_log_records(count: usize) -> Vec<String> {
    debug!("collecting {count} log records");
    ic_log::take_memory_records(count)
}

#[ic_cdk::update(guard = "is_owner")]
pub async fn set_logger_filter(filter: String) {
    LoggerConfigService::default().set_logger_filter(&filter);
    debug!("log filter set to {filter}");
}

#[cfg(test)]
mod tests {
    use ic_log::take_memory_records;
    use log::*;

    use super::*;

    #[test]
    fn update_filter_at_runtime() {
        init_log();

        debug!("This one should be printed");
        info!("This one should be printed");

        LoggerConfigService::default().set_logger_filter("error");

        debug!("This one should NOT be printed");
        info!("This one should NOT be printed");

        LoggerConfigService::default().set_logger_filter("info");

        debug!("This one should NOT be printed");
        info!("This one should be printed");
        let log_records = take_memory_records(5);
        for r in log_records.iter() {
            print!("log_record: {r}")
        }
    }
}

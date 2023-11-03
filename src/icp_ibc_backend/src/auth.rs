use crate::{Error, STATE};
use candid::types::principal::Principal;
use log::info;

pub fn is_authorized() -> Result<(), String> {
    STATE.with_borrow(|s| {
        let caller = ic_cdk::api::caller();
        if !s.owner.eq(&Some(caller)) && !s.relayers.contains(&caller) {
            Err("Unauthorized!".into())
        } else {
            Ok(())
        }
    })
}

pub fn is_owner() -> Result<(), String> {
    STATE.with_borrow(|s| {
        let caller = ic_cdk::api::caller();
        if !s.owner.eq(&Some(caller)) {
            Err("Not Owner!".into())
        } else {
            Ok(())
        }
    })
}

#[ic_cdk::update(guard = "is_owner")]
pub async fn set_relayer(principal: Principal, authorized: bool) -> Result<(), Error> {
    info!("principal: {principal:?}, authorized {authorized:?}");
    if authorized {
        STATE.with_borrow_mut(|s| {
            s.relayers.insert(principal);
        });
    } else {
        STATE.with_borrow_mut(|s| {
            s.relayers.remove(&principal);
        });
    }
    Ok(())
}

#[ic_cdk::update(guard = "is_owner")]
pub async fn set_owner(principal: Principal) -> Result<(), Error> {
    STATE.with_borrow_mut(|s| {
        s.owner = Some(principal);
    });
    info!("new owner: {principal:?}");
    Ok(())
}

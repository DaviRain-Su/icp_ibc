extern crate alloc;

mod ibc_impl;

// use candid::types::principal::Principal;
// use ibc_impl::context::MockContext;

// use std::cell::RefCell;
// use std::collections::HashSet;

// thread_local! {
//     static STATE: RefCell<State> = RefCell::new(State::default());
// }

// #[derive(Debug)]
// struct State {
//     ctx: MockContext,
//     latest_sequence: u64,
//     is_frozen: bool,
//     diversifier: String,
//     owner: Option<Principal>,
//     relayers: HashSet<Principal>,
// }

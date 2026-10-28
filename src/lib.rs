//! The briq credential gateway: the proxy a team's briqs reach the internet through. See README.md.

pub mod log;

pub mod ca;
pub mod config;
pub mod events;
pub mod proxy;
pub mod rewrite;

/// The error every body and client in the gateway carries.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

//! The briq credential gateway: the proxy a team's briqs reach the internet through. See README.md.

pub mod log;

pub mod budget;
mod retained;

pub mod ca;
pub mod config;
pub mod dialer;
pub mod egress;
pub mod events;
pub mod fd;
pub mod proxy;
pub mod rewrite;
pub mod status;

/// The error every body and client in the gateway carries.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

//! The gateway against a fake API and a fake destination, with curl as the client, as a briq's
//! tools would be: the destination gets the real value, the client never does.

include!("gateway/shared.rs");

include!("gateway/scenarios/secrets.rs");

include!("gateway/scenarios/config_and_streaming.rs");

include!("gateway/scenarios/admission_and_budgets.rs");

include!("gateway/scenarios/encoding_bounds.rs");

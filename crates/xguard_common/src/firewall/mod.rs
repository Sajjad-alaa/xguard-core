//! XGuard firewall: rules admins manage, and the per-location policy compiled from them for
//! gateways. See `docs/firewall.md` in the XGuard workspace for the design.

pub mod address;
pub mod allowed_ips;
pub mod compile;
pub mod rule;
pub mod snat;
#[cfg(test)]
mod tests;

pub use allowed_ips::effective_allowed_ips;
pub use compile::{CompiledPolicy, CompiledRule, CompiledSnat, PolicyAction, compile};
pub use rule::{FirewallRule, FirewallRuleAction, FirewallRuleError, FirewallRuleInput};
pub use snat::{SnatBinding, SnatBindingInput, SnatError};

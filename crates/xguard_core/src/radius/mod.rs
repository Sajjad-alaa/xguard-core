//! RADIUS MFA client (RFC 2865 PAP + RFC 3579 Message-Authenticator / BlastRADIUS).

pub mod client;
pub mod packet;

#[cfg(test)]
mod tests;

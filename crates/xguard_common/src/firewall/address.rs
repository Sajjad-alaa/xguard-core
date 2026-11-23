//! Parsing and canonical forms of the destinations and ports admins type into firewall rules.
//!
//! Input is accepted in a few familiar forms and stored canonically, so equal rules compare
//! equal and the compiler never has to re-guess what a string meant.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::RangeInclusive,
    str::FromStr,
};

use ipnetwork::IpNetwork;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AddressError {
    #[error("\"{0}\" is not an IP address, CIDR network or address range")]
    Unparsable(String),
    #[error("\"{0}\": a range must start and end in the same IP version")]
    MixedFamilies(String),
    #[error("\"{0}\": the range start is after its end")]
    Reversed(String),
    #[error("\"{0}\" is not a port or port range between 1 and 65535")]
    BadPort(String),
}

/// An inclusive address range of one IP version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub enum AddressRange {
    V4(Ipv4Addr, Ipv4Addr),
    V6(Ipv6Addr, Ipv6Addr),
}

impl AddressRange {
    #[must_use]
    pub fn single(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(a) => Self::V4(a, a),
            IpAddr::V6(a) => Self::V6(a, a),
        }
    }

    #[must_use]
    pub fn network(network: IpNetwork) -> Self {
        match network {
            IpNetwork::V4(n) => Self::V4(n.network(), n.broadcast()),
            IpNetwork::V6(n) => {
                let bits = u128::from(n.network());
                let host_mask = u128::MAX.checked_shr(u32::from(n.prefix())).unwrap_or(0);
                Self::V6(n.network(), Ipv6Addr::from(bits | host_mask))
            }
        }
    }

    /// Whether `address` lies in this range.
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        match (*self, address) {
            (Self::V4(s, e), IpAddr::V4(a)) => s <= a && a <= e,
            (Self::V6(s, e), IpAddr::V6(a)) => s <= a && a <= e,
            _ => false,
        }
    }

    /// The smallest list of CIDR networks that covers exactly this range, in address order.
    /// At most 2 x (address bits) networks.
    #[must_use]
    pub fn to_networks(&self) -> Vec<IpNetwork> {
        match *self {
            Self::V4(s, e) => cidr_blocks(u128::from(u32::from(s)), u128::from(u32::from(e)), 32)
                .into_iter()
                .filter_map(|(start, prefix)| {
                    let start = u32::try_from(start).ok()?;
                    IpNetwork::new(Ipv4Addr::from(start).into(), prefix).ok()
                })
                .collect(),
            Self::V6(s, e) => cidr_blocks(u128::from(s), u128::from(e), 128)
                .into_iter()
                .filter_map(|(start, prefix)| {
                    IpNetwork::new(Ipv6Addr::from(start).into(), prefix).ok()
                })
                .collect(),
        }
    }

    #[must_use]
    pub fn start(&self) -> IpAddr {
        match *self {
            Self::V4(s, _) => s.into(),
            Self::V6(s, _) => s.into(),
        }
    }

    #[must_use]
    pub fn end(&self) -> IpAddr {
        match *self {
            Self::V4(_, e) => e.into(),
            Self::V6(_, e) => e.into(),
        }
    }
}

/// Splits `start..=end` (addresses of a `bits`-bit family) into aligned blocks, largest first
/// at each step: `(block start, prefix length)`.
fn cidr_blocks(start: u128, end: u128, bits: u32) -> Vec<(u128, u8)> {
    let mut blocks = Vec::new();
    let mut current = start;
    loop {
        // The largest block that starts at `current` (alignment) and does not pass `end` (size).
        let alignment = current.trailing_zeros().min(bits);
        let remaining = end - current;
        let size = if remaining == u128::MAX {
            128
        } else {
            127 - (remaining + 1).leading_zeros()
        };
        let host_bits = alignment.min(size);
        let prefix = u8::try_from(bits - host_bits).expect("prefix fits in u8");
        blocks.push((current, prefix));
        let last = if host_bits >= 128 {
            u128::MAX
        } else {
            current | ((1u128 << host_bits) - 1)
        };
        if last >= end {
            return blocks;
        }
        current = last + 1;
    }
}

/// Parses one destination: `10.0.0.1`, `10.0.0.0/24`, `10.0.0.1-10.0.0.9` or the IPv6 forms.
/// Returns the canonical text to store and the range it covers.
pub fn parse_destination(input: &str) -> Result<(String, AddressRange), AddressError> {
    let text = input.trim();
    let unparsable = || AddressError::Unparsable(input.to_string());

    if let Some((start, end)) = text.split_once('-') {
        let start = IpAddr::from_str(start.trim()).map_err(|_| unparsable())?;
        let end = IpAddr::from_str(end.trim()).map_err(|_| unparsable())?;
        let range = match (start, end) {
            (IpAddr::V4(s), IpAddr::V4(e)) => AddressRange::V4(s, e),
            (IpAddr::V6(s), IpAddr::V6(e)) => AddressRange::V6(s, e),
            _ => return Err(AddressError::MixedFamilies(input.to_string())),
        };
        if start > end {
            return Err(AddressError::Reversed(input.to_string()));
        }
        if start == end {
            return Ok((start.to_string(), range));
        }
        return Ok((format!("{start}-{end}"), range));
    }

    if text.contains('/') {
        let network = IpNetwork::from_str(text).map_err(|_| unparsable())?;
        // Store the network address, not whatever host bits were typed (10.0.0.7/24 -> 10.0.0.0/24).
        let canonical =
            IpNetwork::new(network.network(), network.prefix()).map_err(|_| unparsable())?;
        let range = AddressRange::network(canonical);
        if network.prefix() == max_prefix(network.ip()) {
            return Ok((network.ip().to_string(), range));
        }
        return Ok((canonical.to_string(), range));
    }

    let address = IpAddr::from_str(text).map_err(|_| unparsable())?;
    Ok((address.to_string(), AddressRange::single(address)))
}

fn max_prefix(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// Parses `443` or `8000-8080`. Returns the canonical text and the range.
pub fn parse_ports(input: &str) -> Result<(String, RangeInclusive<u16>), AddressError> {
    let bad = || AddressError::BadPort(input.to_string());
    let text = input.trim();
    let (start, end) = match text.split_once('-') {
        Some((s, e)) => (s.trim(), e.trim()),
        None => (text, text),
    };
    let start: u16 = start.parse().map_err(|_| bad())?;
    let end: u16 = end.parse().map_err(|_| bad())?;
    if start == 0 || start > end {
        return Err(bad());
    }
    let canonical = if start == end {
        start.to_string()
    } else {
        format!("{start}-{end}")
    };
    Ok((canonical, start..=end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destinations_are_canonicalised() {
        let cases = [
            ("10.0.0.1", "10.0.0.1"),
            (" 10.0.0.7/24 ", "10.0.0.0/24"),
            ("10.0.0.5/32", "10.0.0.5"),
            ("10.0.0.1 - 10.0.0.9", "10.0.0.1-10.0.0.9"),
            ("10.0.0.3-10.0.0.3", "10.0.0.3"),
            ("FD00::1", "fd00::1"),
            ("fd00::/8", "fd00::/8"),
        ];
        for (input, expected) in cases {
            assert_eq!(parse_destination(input).unwrap().0, expected, "{input}");
        }
    }

    #[test]
    fn network_ranges_cover_the_whole_block() {
        assert_eq!(
            parse_destination("192.168.4.0/22").unwrap().1,
            AddressRange::V4(
                Ipv4Addr::new(192, 168, 4, 0),
                Ipv4Addr::new(192, 168, 7, 255)
            )
        );
        assert_eq!(
            parse_destination("fd00::/120").unwrap().1,
            AddressRange::V6("fd00::".parse().unwrap(), "fd00::ff".parse().unwrap())
        );
        assert_eq!(
            parse_destination("::/0").unwrap().1,
            AddressRange::V6(Ipv6Addr::UNSPECIFIED, Ipv6Addr::from(u128::MAX))
        );
    }

    #[test]
    fn bad_destinations_are_rejected() {
        for input in [
            "",
            "example.com",
            "10.0.0.300",
            "10.0.0.0/33",
            "1.2.3.4; drop",
        ] {
            assert!(
                matches!(parse_destination(input), Err(AddressError::Unparsable(_))),
                "{input}"
            );
        }
        assert!(matches!(
            parse_destination("10.0.0.1-fd00::1"),
            Err(AddressError::MixedFamilies(_))
        ));
        assert!(matches!(
            parse_destination("10.0.0.9-10.0.0.1"),
            Err(AddressError::Reversed(_))
        ));
    }

    fn networks(range: &str) -> Vec<String> {
        parse_destination(range)
            .unwrap()
            .1
            .to_networks()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn ranges_become_minimal_cidrs() {
        assert_eq!(networks("10.0.0.0/24"), ["10.0.0.0/24"]);
        assert_eq!(networks("10.0.0.5"), ["10.0.0.5/32"]);
        assert_eq!(
            networks("10.0.0.1-10.0.0.6"),
            ["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"]
        );
        assert_eq!(
            networks("10.0.0.0-10.0.1.255"),
            ["10.0.0.0/23"],
            "a range on block boundaries is one network"
        );
        assert_eq!(networks("0.0.0.0/0"), ["0.0.0.0/0"]);
        assert_eq!(networks("0.0.0.0-255.255.255.254").len(), 32);
        assert_eq!(networks("::/0"), ["::/0"]);
        assert_eq!(networks("fd00::1-fd00::2"), ["fd00::1/128", "fd00::2/128"]);
        assert_eq!(
            networks("::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe").len(),
            254,
            "worst case is bounded by twice the address bits"
        );
    }

    #[test]
    fn range_contains() {
        let range = parse_destination("10.0.0.0/24").unwrap().1;
        assert!(range.contains("10.0.0.53".parse().unwrap()));
        assert!(!range.contains("10.0.1.1".parse().unwrap()));
        assert!(!range.contains("fd00::1".parse().unwrap()));
    }

    #[test]
    fn ports() {
        assert_eq!(parse_ports(" 443 ").unwrap(), ("443".into(), 443..=443));
        assert_eq!(
            parse_ports("8000 - 8080").unwrap(),
            ("8000-8080".into(), 8000..=8080)
        );
        for input in ["0", "65536", "90-80", "http", "-1", "1-"] {
            assert!(parse_ports(input).is_err(), "{input}");
        }
    }
}

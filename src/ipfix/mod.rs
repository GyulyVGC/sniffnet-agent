pub mod encode;
pub mod template;

pub const VERSION: u16 = 0x000A;
pub const TEMPLATE_SET_ID: u16 = 2;
pub const TEMPLATE_ID_V4: u16 = 256;
pub const TEMPLATE_ID_V6: u16 = 257;

/// IPFIX message header (RFC 7011 §3.1): `version(2)` + `length(2)` +
/// `export_time(4)` + `sequence(4)` + `obs_domain_id(4)` = 16 bytes.
pub const MSG_HEADER_LEN: u16 = 16;

/// Canonical record size for the IPv4 flow template.
/// 4 + 4 + 2 + 2 + 1 + 6 + 6 + 2 + 2 + 1 + 8 + 8 + 8 + 8 = 62
pub const RECORD_SIZE_V4: u16 = 62;

/// Canonical record size for the IPv6 flow template.
/// 16 + 16 + 2 + 2 + 1 + 6 + 6 + 2 + 2 + 1 + 8 + 8 + 8 + 8 = 86
pub const RECORD_SIZE_V6: u16 = 86;

/// Set header length per RFC 7011 §3.3.
pub const SET_HEADER_LEN: u16 = 4;

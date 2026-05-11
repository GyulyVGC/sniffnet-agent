pub mod encode;
pub mod template;

pub const VERSION: u16 = 0x000A;
pub const TEMPLATE_SET_ID: u16 = 2;
pub const TEMPLATE_ID_V4: u16 = 256;
pub const TEMPLATE_ID_V6: u16 = 257;

/// Canonical record size for the IPv4 flow template.
/// 4 + 4 + 2 + 2 + 1 + 6 + 6 + 8 + 8 = 41
pub const RECORD_SIZE_V4: usize = 41;

/// Canonical record size for the IPv6 flow template.
/// 16 + 16 + 2 + 2 + 1 + 6 + 6 + 8 + 8 = 65
pub const RECORD_SIZE_V6: usize = 65;

/// IPFIX message header length per RFC 7011 §3.1.
pub const MSG_HEADER_LEN: usize = 16;

/// Set header length per RFC 7011 §3.3.
pub const SET_HEADER_LEN: usize = 4;

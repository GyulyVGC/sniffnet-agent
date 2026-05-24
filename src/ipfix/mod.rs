pub mod encode;
pub mod template;

pub const VERSION: u16 = 0x000A;
pub const TEMPLATE_SET_ID: u16 = 2;
pub const TEMPLATE_ID_V4: u16 = 256;
pub const TEMPLATE_ID_V6: u16 = 257;

/// Canonical record size for the IPv4 flow template.
/// 4 + 4 + 2 + 2 + 1 + 6 + 6 + 1 + 8 + 8 + 8 + 8 = 58
pub const RECORD_SIZE_V4: usize = 58;

/// Canonical record size for the IPv6 flow template.
/// 16 + 16 + 2 + 2 + 1 + 6 + 6 + 1 + 8 + 8 + 8 + 8 = 82
pub const RECORD_SIZE_V6: usize = 82;

/// Set header length per RFC 7011 §3.3.
pub const SET_HEADER_LEN: usize = 4;

//! The uapi numbers rtnetlink speaks: `linux/rtnetlink.h`,
//! `linux/fib_rules.h`, `linux/if_link.h`, `linux/if_addr.h` and
//! `linux/if.h`. They are the same on every architecture, so the encoder
//! builds (and is tested) anywhere. The netlink ones (`NLM_F_*`,
//! `NLMSG_*`) are nft's, in `nft::sys`.

// Linux's address families; not libc's, which are the host's (macOS has
// AF_INET6 = 30).
pub const AF_UNSPEC: u8 = 0;
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

// enum rtm message types
pub const RTM_NEWLINK: u16 = 16;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;
pub const RTM_NEWRULE: u16 = 32;
pub const RTM_DELRULE: u16 = 33;

// enum rtattr_type_t
pub const RTA_DST: u16 = 1;
pub const RTA_OIF: u16 = 4;
pub const RTA_GATEWAY: u16 = 5;
pub const RTA_PRIORITY: u16 = 6;
pub const RTA_MULTIPATH: u16 = 9;
pub const RTA_TABLE: u16 = 15;

// rtm_type
pub const RTN_UNICAST: u8 = 1;
pub const RTN_BLACKHOLE: u8 = 6;
pub const RTN_UNREACHABLE: u8 = 7;
pub const RTN_PROHIBIT: u8 = 8;
pub const RTN_THROW: u8 = 9;

// rtm_protocol
pub const RTPROT_BOOT: u8 = 3;

// enum rt_scope_t
pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RT_SCOPE_LINK: u8 = 253;
pub const RT_SCOPE_NOWHERE: u8 = 255;

// enum rt_class_t
pub const RT_TABLE_UNSPEC: u8 = 0;
pub const RT_TABLE_MAIN: u32 = 254;

// linux/fib_rules.h: the attributes
pub const FRA_DST: u16 = 1;
pub const FRA_SRC: u16 = 2;
pub const FRA_IIFNAME: u16 = 3;
pub const FRA_GOTO: u16 = 4;
pub const FRA_PRIORITY: u16 = 6;
pub const FRA_FWMARK: u16 = 10;
pub const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
pub const FRA_TABLE: u16 = 15;
pub const FRA_FWMASK: u16 = 16;
pub const FRA_OIFNAME: u16 = 17;
pub const FRA_UID_RANGE: u16 = 20;
pub const FRA_IP_PROTO: u16 = 22;
pub const FRA_SPORT_RANGE: u16 = 23;
pub const FRA_DPORT_RANGE: u16 = 24;

// linux/fib_rules.h: the actions, and fib_rule_hdr's flags
pub const FR_ACT_UNSPEC: u8 = 0;
pub const FR_ACT_TO_TBL: u8 = 1;
pub const FR_ACT_GOTO: u8 = 2;
pub const FR_ACT_NOP: u8 = 3;
pub const FR_ACT_UNREACHABLE: u8 = 7;
pub const FIB_RULE_INVERT: u32 = 0x2;

// linux/if_link.h
pub const IFLA_IFNAME: u16 = 3;
pub const IFLA_MTU: u16 = 4;
pub const IFLA_EXT_MASK: u16 = 29;
// linux/rtnetlink.h: leave the statistics out of a link's answer.
pub const RTEXT_FILTER_SKIP_STATS: u32 = 1 << 3;

// linux/if.h
pub const IFF_UP: u32 = 0x1;

// linux/if_addr.h
pub const IFA_ADDRESS: u16 = 1;
pub const IFA_LOCAL: u16 = 2;

/// The sizes of the fixed headers: `struct rtmsg` (and `fib_rule_hdr`,
/// laid out alike), `struct ifinfomsg`, `struct ifaddrmsg`, and
/// `struct rtnexthop`.
pub const RTMSG_LEN: usize = 12;
pub const IFINFOMSG_LEN: usize = 16;
pub const IFADDRMSG_LEN: usize = 8;
pub const RTNEXTHOP_LEN: usize = 8;

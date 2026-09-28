//! The uapi numbers this module speaks: `linux/netlink.h`,
//! `linux/netfilter/nfnetlink.h` and `linux/netfilter/nf_tables.h`. They are
//! the same on every architecture, so the encoder builds (and is tested)
//! anywhere.

// linux/netlink.h
pub const NLMSG_HDRLEN: usize = 16;
pub const NLMSG_ERROR: u16 = 0x2;
pub const NLMSG_DONE: u16 = 0x3;
pub const NLM_F_REQUEST: u16 = 0x1;
pub const NLM_F_MULTI: u16 = 0x2;
pub const NLM_F_ACK: u16 = 0x4;
pub const NLM_F_DUMP: u16 = 0x300;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_APPEND: u16 = 0x800;
/// In an error message: the original message was cut to its header.
pub const NLM_F_CAPPED: u16 = 0x100;
/// In an error message: extended-ack attributes follow.
pub const NLM_F_ACK_TLVS: u16 = 0x200;
pub const NLA_HDRLEN: usize = 4;
pub const NLA_F_NESTED: u16 = 0x8000;
pub const NLA_TYPE_MASK: u16 = 0x3fff;
pub const NLMSGERR_ATTR_MSG: u16 = 1;

// linux/netfilter/nfnetlink.h
pub const NFNETLINK_V0: u8 = 0;
pub const NFNL_SUBSYS_NFTABLES: u16 = 10;
pub const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
pub const NFNL_MSG_BATCH_END: u16 = 0x11;

// enum nf_tables_msg_types
pub const NFT_MSG_NEWTABLE: u16 = 0;
pub const NFT_MSG_GETTABLE: u16 = 1;
pub const NFT_MSG_DELTABLE: u16 = 2;
pub const NFT_MSG_NEWCHAIN: u16 = 3;
pub const NFT_MSG_NEWRULE: u16 = 6;
pub const NFT_MSG_NEWSET: u16 = 9;
pub const NFT_MSG_NEWSETELEM: u16 = 12;
pub const NFT_MSG_DELSETELEM: u16 = 14;

// enum nft_list_attributes
pub const NFTA_LIST_ELEM: u16 = 1;

// enum nft_table_attributes
pub const NFTA_TABLE_NAME: u16 = 1;
pub const NFTA_TABLE_FLAGS: u16 = 2;
pub const NFTA_TABLE_USE: u16 = 3;

// enum nft_chain_attributes, nft_hook_attributes
pub const NFTA_CHAIN_TABLE: u16 = 1;
pub const NFTA_CHAIN_NAME: u16 = 3;
pub const NFTA_CHAIN_HOOK: u16 = 4;
pub const NFTA_CHAIN_POLICY: u16 = 5;
pub const NFTA_CHAIN_TYPE: u16 = 7;
pub const NFTA_HOOK_HOOKNUM: u16 = 1;
pub const NFTA_HOOK_PRIORITY: u16 = 2;

// enum nft_rule_attributes
pub const NFTA_RULE_TABLE: u16 = 1;
pub const NFTA_RULE_CHAIN: u16 = 2;
pub const NFTA_RULE_EXPRESSIONS: u16 = 4;

// enum nft_set_attributes, nft_set_flags, nft_set_desc_attributes
pub const NFTA_SET_TABLE: u16 = 1;
pub const NFTA_SET_NAME: u16 = 2;
pub const NFTA_SET_FLAGS: u16 = 3;
pub const NFTA_SET_KEY_TYPE: u16 = 4;
pub const NFTA_SET_KEY_LEN: u16 = 5;
pub const NFTA_SET_DESC: u16 = 9;
pub const NFTA_SET_ID: u16 = 10;
pub const NFTA_SET_USERDATA: u16 = 13;
pub const NFTA_SET_DESC_SIZE: u16 = 1;
pub const NFT_SET_ANONYMOUS: u32 = 0x1;
pub const NFT_SET_CONSTANT: u32 = 0x2;
pub const NFT_SET_INTERVAL: u32 = 0x4;

// enum nft_set_elem_list_attributes, nft_set_elem_attributes
pub const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
pub const NFTA_SET_ELEM_LIST_SET: u16 = 2;
pub const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;
pub const NFTA_SET_ELEM_LIST_SET_ID: u16 = 4;
pub const NFTA_SET_ELEM_KEY: u16 = 1;
pub const NFTA_SET_ELEM_FLAGS: u16 = 3;
pub const NFT_SET_ELEM_INTERVAL_END: u32 = 0x1;

// enum nft_data_attributes, nft_verdict_attributes, nft_verdicts
pub const NFTA_DATA_VALUE: u16 = 1;
pub const NFTA_DATA_VERDICT: u16 = 2;
pub const NFTA_VERDICT_CODE: u16 = 1;
pub const NFTA_VERDICT_CHAIN: u16 = 2;
pub const NF_DROP: i32 = 0;
pub const NF_ACCEPT: i32 = 1;
pub const NFT_JUMP: i32 = -3;
pub const NFT_GOTO: i32 = -4;
pub const NFT_RETURN: i32 = -5;

// enum nft_expr_attributes
pub const NFTA_EXPR_NAME: u16 = 1;
pub const NFTA_EXPR_DATA: u16 = 2;

// enum nft_immediate_attributes
pub const NFTA_IMMEDIATE_DREG: u16 = 1;
pub const NFTA_IMMEDIATE_DATA: u16 = 2;

// enum nft_bitwise_attributes
pub const NFTA_BITWISE_SREG: u16 = 1;
pub const NFTA_BITWISE_DREG: u16 = 2;
pub const NFTA_BITWISE_LEN: u16 = 3;
pub const NFTA_BITWISE_MASK: u16 = 4;
pub const NFTA_BITWISE_XOR: u16 = 5;

// enum nft_cmp_attributes
pub const NFTA_CMP_SREG: u16 = 1;
pub const NFTA_CMP_OP: u16 = 2;
pub const NFTA_CMP_DATA: u16 = 3;

// enum nft_lookup_attributes
pub const NFTA_LOOKUP_SET: u16 = 1;
pub const NFTA_LOOKUP_SREG: u16 = 2;
pub const NFTA_LOOKUP_SET_ID: u16 = 4;
pub const NFTA_LOOKUP_FLAGS: u16 = 5;
pub const NFT_LOOKUP_F_INV: u32 = 0x1;

// enum nft_payload_attributes
pub const NFTA_PAYLOAD_DREG: u16 = 1;
pub const NFTA_PAYLOAD_BASE: u16 = 2;
pub const NFTA_PAYLOAD_OFFSET: u16 = 3;
pub const NFTA_PAYLOAD_LEN: u16 = 4;

// enum nft_exthdr_attributes
pub const NFTA_EXTHDR_DREG: u16 = 1;
pub const NFTA_EXTHDR_TYPE: u16 = 2;
pub const NFTA_EXTHDR_OFFSET: u16 = 3;
pub const NFTA_EXTHDR_LEN: u16 = 4;
pub const NFTA_EXTHDR_FLAGS: u16 = 5;
pub const NFTA_EXTHDR_OP: u16 = 6;

// enum nft_meta_attributes
pub const NFTA_META_DREG: u16 = 1;
pub const NFTA_META_KEY: u16 = 2;
pub const NFTA_META_SREG: u16 = 3;

// enum nft_ct_attributes
pub const NFTA_CT_DREG: u16 = 1;
pub const NFTA_CT_KEY: u16 = 2;
pub const NFTA_CT_SREG: u16 = 4;

// enum nft_counter_attributes
pub const NFTA_COUNTER_BYTES: u16 = 1;
pub const NFTA_COUNTER_PACKETS: u16 = 2;

// enum nft_reject_attributes
pub const NFTA_REJECT_TYPE: u16 = 1;
pub const NFTA_REJECT_ICMP_CODE: u16 = 2;

// enum nft_nat_attributes
pub const NFTA_NAT_TYPE: u16 = 1;
pub const NFTA_NAT_FAMILY: u16 = 2;
pub const NFTA_NAT_REG_ADDR_MIN: u16 = 3;
pub const NFTA_NAT_REG_PROTO_MIN: u16 = 5;
pub const NFTA_NAT_FLAGS: u16 = 7;

// enum nft_redir_attributes
pub const NFTA_REDIR_REG_PROTO_MIN: u16 = 1;
pub const NFTA_REDIR_FLAGS: u16 = 3;

// enum nft_queue_attributes
pub const NFTA_QUEUE_NUM: u16 = 1;
pub const NFTA_QUEUE_TOTAL: u16 = 2;
pub const NFTA_QUEUE_FLAGS: u16 = 3;

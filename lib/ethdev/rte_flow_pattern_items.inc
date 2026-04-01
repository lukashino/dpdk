/* SPDX-License-Identifier: BSD-3-Clause
 * Shared pattern item arrays - extracted from cmdline_flow.c.
 * DO NOT EDIT: this file is the single source of truth for pattern grammar.
 * Both lib/ethdev/rte_flow_pattern_parser.c and app/test-pmd/cmdline_flow.c
 * include this file.
 */


static const enum index item_param[] = {
	ITEM_PARAM_IS,
	ITEM_PARAM_SPEC,
	ITEM_PARAM_LAST,
	ITEM_PARAM_MASK,
	ITEM_PARAM_PREFIX,
	ZERO,
};

static const enum index next_item[] = {
	ITEM_END,
	ITEM_VOID,
	ITEM_INVERT,
	ITEM_ANY,
	ITEM_PORT_ID,
	ITEM_MARK,
	ITEM_RAW,
	ITEM_ETH,
	ITEM_VLAN,
	ITEM_IPV4,
	ITEM_IPV6,
	ITEM_ICMP,
	ITEM_UDP,
	ITEM_TCP,
	ITEM_SCTP,
	ITEM_VXLAN,
	ITEM_E_TAG,
	ITEM_NVGRE,
	ITEM_MPLS,
	ITEM_GRE,
	ITEM_FUZZY,
	ITEM_GTP,
	ITEM_GTPC,
	ITEM_GTPU,
	ITEM_GENEVE,
	ITEM_VXLAN_GPE,
	ITEM_ARP_ETH_IPV4,
	ITEM_IPV6_EXT,
	ITEM_IPV6_FRAG_EXT,
	ITEM_IPV6_ROUTING_EXT,
	ITEM_ICMP6,
	ITEM_ICMP6_ECHO_REQUEST,
	ITEM_ICMP6_ECHO_REPLY,
	ITEM_ICMP6_ND_NS,
	ITEM_ICMP6_ND_NA,
	ITEM_ICMP6_ND_OPT,
	ITEM_ICMP6_ND_OPT_SLA_ETH,
	ITEM_ICMP6_ND_OPT_TLA_ETH,
	ITEM_META,
	ITEM_RANDOM,
	ITEM_GRE_KEY,
	ITEM_GRE_OPTION,
	ITEM_GTP_PSC,
	ITEM_PPPOES,
	ITEM_PPPOED,
	ITEM_PPPOE_PROTO_ID,
	ITEM_HIGIG2,
	ITEM_TAG,
	ITEM_L2TPV3OIP,
	ITEM_ESP,
	ITEM_AH,
	ITEM_PFCP,
	ITEM_ECPRI,
	ITEM_GENEVE_OPT,
	ITEM_INTEGRITY,
	ITEM_CONNTRACK,
	ITEM_PORT_REPRESENTOR,
	ITEM_REPRESENTED_PORT,
	ITEM_FLEX,
	ITEM_L2TPV2,
	ITEM_PPP,
	ITEM_METER,
	ITEM_QUOTA,
	ITEM_AGGR_AFFINITY,
	ITEM_TX_QUEUE,
	ITEM_IB_BTH,
	ITEM_PTYPE,
	ITEM_NSH,
	ITEM_COMPARE,
	END_SET,
	ZERO,
};

static const enum index item_fuzzy[] = {
	ITEM_FUZZY_THRESH,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_any[] = {
	ITEM_ANY_NUM,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_port_id[] = {
	ITEM_PORT_ID_ID,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_mark[] = {
	ITEM_MARK_ID,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_raw[] = {
	ITEM_RAW_RELATIVE,
	ITEM_RAW_SEARCH,
	ITEM_RAW_OFFSET,
	ITEM_RAW_LIMIT,
	ITEM_RAW_PATTERN,
	ITEM_RAW_PATTERN_HEX,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_eth[] = {
	ITEM_ETH_DST,
	ITEM_ETH_SRC,
	ITEM_ETH_TYPE,
	ITEM_ETH_HAS_VLAN,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_vlan[] = {
	ITEM_VLAN_TCI,
	ITEM_VLAN_PCP,
	ITEM_VLAN_DEI,
	ITEM_VLAN_VID,
	ITEM_VLAN_INNER_TYPE,
	ITEM_VLAN_HAS_MORE_VLAN,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_ipv4[] = {
	ITEM_IPV4_VER_IHL,
	ITEM_IPV4_TOS,
	ITEM_IPV4_LENGTH,
	ITEM_IPV4_ID,
	ITEM_IPV4_FRAGMENT_OFFSET,
	ITEM_IPV4_TTL,
	ITEM_IPV4_PROTO,
	ITEM_IPV4_SRC,
	ITEM_IPV4_DST,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_ipv6[] = {
	ITEM_IPV6_TC,
	ITEM_IPV6_FLOW,
	ITEM_IPV6_LEN,
	ITEM_IPV6_PROTO,
	ITEM_IPV6_HOP,
	ITEM_IPV6_SRC,
	ITEM_IPV6_DST,
	ITEM_IPV6_HAS_FRAG_EXT,
	ITEM_IPV6_ROUTING_EXT,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_ipv6_routing_ext[] = {
	ITEM_IPV6_ROUTING_EXT_TYPE,
	ITEM_IPV6_ROUTING_EXT_NEXT_HDR,
	ITEM_IPV6_ROUTING_EXT_SEG_LEFT,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_icmp[] = {
	ITEM_ICMP_TYPE,
	ITEM_ICMP_CODE,
	ITEM_ICMP_IDENT,
	ITEM_ICMP_SEQ,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_udp[] = {
	ITEM_UDP_SRC,
	ITEM_UDP_DST,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_tcp[] = {
	ITEM_TCP_SRC,
	ITEM_TCP_DST,
	ITEM_TCP_FLAGS,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_sctp[] = {
	ITEM_SCTP_SRC,
	ITEM_SCTP_DST,
	ITEM_SCTP_TAG,
	ITEM_SCTP_CKSUM,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_vxlan[] = {
	ITEM_VXLAN_VNI,
	ITEM_VXLAN_FLAG_G,
	ITEM_VXLAN_FLAG_VER,
	ITEM_VXLAN_FLAG_I,
	ITEM_VXLAN_FLAG_P,
	ITEM_VXLAN_FLAG_B,
	ITEM_VXLAN_FLAG_O,
	ITEM_VXLAN_FLAG_D,
	ITEM_VXLAN_FLAG_A,
	ITEM_VXLAN_GBP_ID,
	ITEM_VXLAN_GPE_PROTO,
	ITEM_VXLAN_FIRST_RSVD,
	ITEM_VXLAN_SECND_RSVD,
	ITEM_VXLAN_THIRD_RSVD,
	ITEM_VXLAN_LAST_RSVD,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_e_tag[] = {
	ITEM_E_TAG_GRP_ECID_B,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_nvgre[] = {
	ITEM_NVGRE_TNI,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_mpls[] = {
	ITEM_MPLS_LABEL,
	ITEM_MPLS_TC,
	ITEM_MPLS_S,
	ITEM_MPLS_TTL,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_gre[] = {
	ITEM_GRE_PROTO,
	ITEM_GRE_C_RSVD0_VER,
	ITEM_GRE_C_BIT,
	ITEM_GRE_K_BIT,
	ITEM_GRE_S_BIT,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_gre_key[] = {
	ITEM_GRE_KEY_VALUE,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_gre_option[] = {
	ITEM_GRE_OPTION_CHECKSUM,
	ITEM_GRE_OPTION_KEY,
	ITEM_GRE_OPTION_SEQUENCE,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_gtp[] = {
	ITEM_GTP_FLAGS,
	ITEM_GTP_MSG_TYPE,
	ITEM_GTP_TEID,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_geneve[] = {
	ITEM_GENEVE_VNI,
	ITEM_GENEVE_PROTO,
	ITEM_GENEVE_OPTLEN,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_vxlan_gpe[] = {
	ITEM_VXLAN_GPE_VNI,
	ITEM_VXLAN_GPE_PROTO_IN_DEPRECATED_VXLAN_GPE_HDR,
	ITEM_VXLAN_GPE_FLAGS,
	ITEM_VXLAN_GPE_RSVD0,
	ITEM_VXLAN_GPE_RSVD1,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_arp_eth_ipv4[] = {
	ITEM_ARP_ETH_IPV4_SHA,
	ITEM_ARP_ETH_IPV4_SPA,
	ITEM_ARP_ETH_IPV4_THA,
	ITEM_ARP_ETH_IPV4_TPA,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_ipv6_ext[] = {
	ITEM_IPV6_EXT_NEXT_HDR,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_ipv6_frag_ext[] = {
	ITEM_IPV6_FRAG_EXT_NEXT_HDR,
	ITEM_IPV6_FRAG_EXT_FRAG_DATA,
	ITEM_IPV6_FRAG_EXT_ID,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_icmp6[] = {
	ITEM_ICMP6_TYPE,
	ITEM_ICMP6_CODE,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_icmp6_echo_request[] = {
	ITEM_ICMP6_ECHO_REQUEST_ID,
	ITEM_ICMP6_ECHO_REQUEST_SEQ,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_icmp6_echo_reply[] = {
	ITEM_ICMP6_ECHO_REPLY_ID,
	ITEM_ICMP6_ECHO_REPLY_SEQ,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_icmp6_nd_ns[] = {
	ITEM_ICMP6_ND_NS_TARGET_ADDR,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_icmp6_nd_na[] = {
	ITEM_ICMP6_ND_NA_TARGET_ADDR,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_icmp6_nd_opt[] = {
	ITEM_ICMP6_ND_OPT_TYPE,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_icmp6_nd_opt_sla_eth[] = {
	ITEM_ICMP6_ND_OPT_SLA_ETH_SLA,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_icmp6_nd_opt_tla_eth[] = {
	ITEM_ICMP6_ND_OPT_TLA_ETH_TLA,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_meta[] = {
	ITEM_META_DATA,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_random[] = {
	ITEM_RANDOM_VALUE,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_gtp_psc[] = {
	ITEM_GTP_PSC_QFI,
	ITEM_GTP_PSC_PDU_T,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_pppoed[] = {
	ITEM_PPPOE_SEID,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_pppoes[] = {
	ITEM_PPPOE_SEID,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_pppoe_proto_id[] = {
	ITEM_NEXT,
	ZERO,
};

static const enum index item_higig2[] = {
	ITEM_HIGIG2_CLASSIFICATION,
	ITEM_HIGIG2_VID,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_esp[] = {
	ITEM_ESP_SPI,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_ah[] = {
	ITEM_AH_SPI,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_pfcp[] = {
	ITEM_PFCP_S_FIELD,
	ITEM_PFCP_SEID,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_tag[] = {
	ITEM_TAG_DATA,
	ITEM_TAG_INDEX,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_l2tpv3oip[] = {
	ITEM_L2TPV3OIP_SESSION_ID,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_ecpri[] = {
	ITEM_ECPRI_COMMON,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_ecpri_common[] = {
	ITEM_ECPRI_COMMON_TYPE,
	ZERO,
};

static const enum index item_ecpri_common_type[] = {
	ITEM_ECPRI_COMMON_TYPE_IQ_DATA,
	ITEM_ECPRI_COMMON_TYPE_RTC_CTRL,
	ITEM_ECPRI_COMMON_TYPE_DLY_MSR,
	ZERO,
};

static const enum index item_geneve_opt[] = {
	ITEM_GENEVE_OPT_CLASS,
	ITEM_GENEVE_OPT_TYPE,
	ITEM_GENEVE_OPT_LENGTH,
	ITEM_GENEVE_OPT_DATA,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_integrity[] = {
	ITEM_INTEGRITY_LEVEL,
	ITEM_INTEGRITY_VALUE,
	ZERO,
};

static const enum index item_integrity_lv[] = {
	ITEM_INTEGRITY_LEVEL,
	ITEM_INTEGRITY_VALUE,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_port_representor[] = {
	ITEM_PORT_REPRESENTOR_PORT_ID,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_represented_port[] = {
	ITEM_REPRESENTED_PORT_ETHDEV_PORT_ID,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_flex[] = {
	ITEM_FLEX_PATTERN_HANDLE,
	ITEM_FLEX_ITEM_HANDLE,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_l2tpv2[] = {
	ITEM_L2TPV2_TYPE,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_l2tpv2_type[] = {
	ITEM_L2TPV2_TYPE_DATA,
	ITEM_L2TPV2_TYPE_DATA_L,
	ITEM_L2TPV2_TYPE_DATA_S,
	ITEM_L2TPV2_TYPE_DATA_O,
	ITEM_L2TPV2_TYPE_DATA_L_S,
	ITEM_L2TPV2_TYPE_CTRL,
	ZERO,
};

static const enum index item_l2tpv2_type_data[] = {
	ITEM_L2TPV2_MSG_DATA_TUNNEL_ID,
	ITEM_L2TPV2_MSG_DATA_SESSION_ID,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_l2tpv2_type_data_l[] = {
	ITEM_L2TPV2_MSG_DATA_L_LENGTH,
	ITEM_L2TPV2_MSG_DATA_L_TUNNEL_ID,
	ITEM_L2TPV2_MSG_DATA_L_SESSION_ID,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_l2tpv2_type_data_s[] = {
	ITEM_L2TPV2_MSG_DATA_S_TUNNEL_ID,
	ITEM_L2TPV2_MSG_DATA_S_SESSION_ID,
	ITEM_L2TPV2_MSG_DATA_S_NS,
	ITEM_L2TPV2_MSG_DATA_S_NR,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_l2tpv2_type_data_o[] = {
	ITEM_L2TPV2_MSG_DATA_O_TUNNEL_ID,
	ITEM_L2TPV2_MSG_DATA_O_SESSION_ID,
	ITEM_L2TPV2_MSG_DATA_O_OFFSET,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_l2tpv2_type_data_l_s[] = {
	ITEM_L2TPV2_MSG_DATA_L_S_LENGTH,
	ITEM_L2TPV2_MSG_DATA_L_S_TUNNEL_ID,
	ITEM_L2TPV2_MSG_DATA_L_S_SESSION_ID,
	ITEM_L2TPV2_MSG_DATA_L_S_NS,
	ITEM_L2TPV2_MSG_DATA_L_S_NR,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_l2tpv2_type_ctrl[] = {
	ITEM_L2TPV2_MSG_CTRL_LENGTH,
	ITEM_L2TPV2_MSG_CTRL_TUNNEL_ID,
	ITEM_L2TPV2_MSG_CTRL_SESSION_ID,
	ITEM_L2TPV2_MSG_CTRL_NS,
	ITEM_L2TPV2_MSG_CTRL_NR,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_ppp[] = {
	ITEM_PPP_ADDR,
	ITEM_PPP_CTRL,
	ITEM_PPP_PROTO_ID,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_meter[] = {
	ITEM_METER_COLOR,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_quota[] = {
	ITEM_QUOTA_STATE,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_aggr_affinity[] = {
	ITEM_AGGR_AFFINITY_VALUE,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_tx_queue[] = {
	ITEM_TX_QUEUE_VALUE,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_ib_bth[] = {
	ITEM_IB_BTH_OPCODE,
	ITEM_IB_BTH_PKEY,
	ITEM_IB_BTH_DST_QPN,
	ITEM_IB_BTH_PSN,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_ptype[] = {
	ITEM_PTYPE_VALUE,
	ITEM_NEXT,
	ZERO,
};

static const enum index item_nsh[] = {
	ITEM_NEXT,
	ZERO,
};

static const enum index item_compare_field[] = {
	ITEM_COMPARE_OP,
	ITEM_COMPARE_FIELD_A_TYPE,
	ITEM_COMPARE_FIELD_B_TYPE,
	ITEM_NEXT,
	ZERO,
};

static const enum index compare_field_a[] = {
	ITEM_COMPARE_FIELD_A_TYPE,
	ITEM_COMPARE_FIELD_A_LEVEL,
	ITEM_COMPARE_FIELD_A_TAG_INDEX,
	ITEM_COMPARE_FIELD_A_TYPE_ID,
	ITEM_COMPARE_FIELD_A_CLASS_ID,
	ITEM_COMPARE_FIELD_A_OFFSET,
	ITEM_COMPARE_FIELD_B_TYPE,
	ZERO,
};

static const enum index compare_field_b[] = {
	ITEM_COMPARE_FIELD_B_TYPE,
	ITEM_COMPARE_FIELD_B_LEVEL,
	ITEM_COMPARE_FIELD_B_TAG_INDEX,
	ITEM_COMPARE_FIELD_B_TYPE_ID,
	ITEM_COMPARE_FIELD_B_CLASS_ID,
	ITEM_COMPARE_FIELD_B_OFFSET,
	ITEM_COMPARE_FIELD_B_VALUE,
	ITEM_COMPARE_FIELD_B_POINTER,
	ITEM_COMPARE_FIELD_WIDTH,
	ZERO,
};

static const enum index item_ipv6_push_ext[] = {
	ITEM_IPV6_PUSH_REMOVE_EXT,
	ZERO,
};

static const enum index item_ipv6_push_ext_type[] = {
	ITEM_IPV6_PUSH_REMOVE_EXT_TYPE,
	ZERO,
};

static const enum index item_ipv6_push_ext_header[] = {
	ITEM_IPV6_ROUTING_EXT,
	ITEM_NEXT,
	ZERO,
};

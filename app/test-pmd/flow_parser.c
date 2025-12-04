/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <string.h>

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_geneve.h>
#include <rte_gre.h>
#include <rte_gtp.h>
#include <rte_mpls.h>
#include <rte_string_fns.h>
#include <rte_vxlan.h>
#include <rte_ip.h>
#include <rte_flow.h>
#include <rte_flow_parser.h>

#include "testpmd.h"

struct rte_flow_parser_vxlan_encap_conf vxlan_encap_conf;
struct rte_flow_parser_nvgre_encap_conf nvgre_encap_conf;
struct rte_flow_parser_l2_encap_conf l2_encap_conf;
struct rte_flow_parser_l2_decap_conf l2_decap_conf;
struct rte_flow_parser_mplsogre_encap_conf mplsogre_encap_conf;
struct rte_flow_parser_mplsogre_decap_conf mplsogre_decap_conf;
struct rte_flow_parser_mplsoudp_encap_conf mplsoudp_encap_conf;
struct rte_flow_parser_mplsoudp_decap_conf mplsoudp_decap_conf;

struct action_vxlan_encap_data {
	struct rte_flow_action_vxlan_encap conf;
	struct rte_flow_item items[ACTION_VXLAN_ENCAP_ITEMS_NUM];
	struct rte_flow_item_eth item_eth;
	struct rte_flow_item_vlan item_vlan;
	union {
		struct rte_flow_item_ipv4 item_ipv4;
		struct rte_flow_item_ipv6 item_ipv6;
	};
	struct rte_flow_item_udp item_udp;
	struct rte_flow_item_vxlan item_vxlan;
};

struct action_nvgre_encap_data {
	struct rte_flow_action_nvgre_encap conf;
	struct rte_flow_item items[ACTION_NVGRE_ENCAP_ITEMS_NUM];
	struct rte_flow_item_eth item_eth;
	struct rte_flow_item_vlan item_vlan;
	union {
		struct rte_flow_item_ipv4 item_ipv4;
		struct rte_flow_item_ipv6 item_ipv6;
	};
	struct rte_flow_item_nvgre item_nvgre;
};

struct raw_encap_conf {
	uint8_t data[ACTION_RAW_ENCAP_MAX_DATA];
	uint8_t preserve[ACTION_RAW_ENCAP_MAX_DATA];
	size_t size;
};

struct raw_decap_conf {
	uint8_t data[ACTION_RAW_ENCAP_MAX_DATA];
	size_t size;
};

struct ipv6_ext_push_conf {
	uint8_t data[ACTION_IPV6_EXT_PUSH_MAX_DATA];
	size_t size;
	uint8_t type;
};

struct ipv6_ext_remove_conf {
	uint8_t type;
};

struct raw_sample_conf {
	struct rte_flow_action data[ACTION_SAMPLE_ACTIONS_NUM];
};

struct action_rss_data {
	struct rte_flow_action_rss conf;
	uint8_t key[RSS_HASH_KEY_LENGTH];
	uint16_t queue[ACTION_RSS_QUEUE_NUM];
};

struct parser_storage {
	struct raw_encap_conf raw_encap_confs[RAW_ENCAP_CONFS_MAX_NUM];
	struct raw_decap_conf raw_decap_confs[RAW_ENCAP_CONFS_MAX_NUM];
	struct ipv6_ext_push_conf ipv6_ext_push_confs[IPV6_EXT_PUSH_CONFS_MAX_NUM];
	struct ipv6_ext_remove_conf ipv6_ext_remove_confs[IPV6_EXT_PUSH_CONFS_MAX_NUM];
	struct rte_flow_action_raw_encap
		raw_encap_conf_cache[RAW_ENCAP_CONFS_MAX_NUM];
	struct rte_flow_action_raw_decap
		raw_decap_conf_cache[RAW_ENCAP_CONFS_MAX_NUM];
	struct rte_flow_action_ipv6_ext_push
		ipv6_ext_push_action_cache[IPV6_EXT_PUSH_CONFS_MAX_NUM];
	struct rte_flow_action_ipv6_ext_remove
		ipv6_ext_remove_action_cache[IPV6_EXT_PUSH_CONFS_MAX_NUM];
	struct raw_sample_conf raw_sample_confs[RAW_SAMPLE_CONFS_MAX_NUM];
	struct rte_flow_action_mark sample_mark[RAW_SAMPLE_CONFS_MAX_NUM];
	struct rte_flow_action_queue sample_queue[RAW_SAMPLE_CONFS_MAX_NUM];
	struct rte_flow_action_count sample_count[RAW_SAMPLE_CONFS_MAX_NUM];
	struct rte_flow_action_port_id sample_port_id[RAW_SAMPLE_CONFS_MAX_NUM];
	struct rte_flow_action_raw_encap sample_encap[RAW_SAMPLE_CONFS_MAX_NUM];
	struct action_vxlan_encap_data sample_vxlan_encap[RAW_SAMPLE_CONFS_MAX_NUM];
	struct action_nvgre_encap_data sample_nvgre_encap[RAW_SAMPLE_CONFS_MAX_NUM];
	struct action_rss_data sample_rss_data[RAW_SAMPLE_CONFS_MAX_NUM];
	struct rte_flow_action_vf sample_vf[RAW_SAMPLE_CONFS_MAX_NUM];
	struct rte_flow_action_ethdev sample_port_representor[RAW_SAMPLE_CONFS_MAX_NUM];
	struct rte_flow_action_ethdev sample_represented_port[RAW_SAMPLE_CONFS_MAX_NUM];
};

static struct parser_storage parser_store;

static struct parser_storage *
parser_storage(void)
{
	return &parser_store;
}

static void
flow_parser_reset_defaults(void)
{
	vxlan_encap_conf = rte_flow_parser_default_vxlan_encap_conf;
	nvgre_encap_conf = rte_flow_parser_default_nvgre_encap_conf;
	l2_encap_conf = rte_flow_parser_default_l2_encap_conf;
	l2_decap_conf = rte_flow_parser_default_l2_decap_conf;
	mplsogre_encap_conf = rte_flow_parser_default_mplsogre_encap_conf;
	mplsogre_decap_conf = rte_flow_parser_default_mplsogre_decap_conf;
	mplsoudp_encap_conf = rte_flow_parser_default_mplsoudp_encap_conf;
	mplsoudp_decap_conf = rte_flow_parser_default_mplsoudp_decap_conf;
}

static void
update_fields(uint8_t *buf, struct rte_flow_item *item, uint16_t next_proto)
{
	struct rte_ipv4_hdr *ipv4;
	struct rte_ether_hdr *eth;
	struct rte_ipv6_hdr *ipv6;
	struct rte_vxlan_hdr *vxlan;
	struct rte_vxlan_gpe_hdr *gpe;
	struct rte_flow_item_nvgre *nvgre;
	uint32_t ipv6_vtc_flow;

	switch (item->type) {
	case RTE_FLOW_ITEM_TYPE_ETH:
		eth = (struct rte_ether_hdr *)buf;
		if (next_proto)
			eth->ether_type = rte_cpu_to_be_16(next_proto);
		break;
	case RTE_FLOW_ITEM_TYPE_IPV4:
		ipv4 = (struct rte_ipv4_hdr *)buf;
		if (!ipv4->version_ihl)
			ipv4->version_ihl = RTE_IPV4_VHL_DEF;
		if (next_proto && ipv4->next_proto_id == 0)
			ipv4->next_proto_id = (uint8_t)next_proto;
		break;
	case RTE_FLOW_ITEM_TYPE_IPV6:
		ipv6 = (struct rte_ipv6_hdr *)buf;
		if (next_proto && ipv6->proto == 0)
			ipv6->proto = (uint8_t)next_proto;
		ipv6_vtc_flow = rte_be_to_cpu_32(ipv6->vtc_flow);
		ipv6_vtc_flow &= 0x0FFFFFFF;
		ipv6_vtc_flow |= 0x60000000;
		ipv6->vtc_flow = rte_cpu_to_be_32(ipv6_vtc_flow);
		break;
	case RTE_FLOW_ITEM_TYPE_VXLAN:
		vxlan = (struct rte_vxlan_hdr *)buf;
		if (!vxlan->flags)
			vxlan->flags = 0x08;
		break;
	case RTE_FLOW_ITEM_TYPE_VXLAN_GPE:
		gpe = (struct rte_vxlan_gpe_hdr *)buf;
		gpe->vx_flags = 0x0C;
		break;
	case RTE_FLOW_ITEM_TYPE_NVGRE:
		nvgre = (struct rte_flow_item_nvgre *)buf;
		nvgre->protocol = rte_cpu_to_be_16(0x6558);
		nvgre->c_k_s_rsvd0_ver = rte_cpu_to_be_16(0x2000);
		break;
	default:
		break;
	}
}

static const void *
flow_item_default_mask(const struct rte_flow_item *item)
{
	const void *mask = NULL;
	static rte_be32_t gre_key_default_mask = RTE_BE32(UINT32_MAX);
	static struct rte_flow_item_ipv6_routing_ext ipv6_routing_ext_default_mask = {
		.hdr = {
			.next_hdr = 0xff,
			.type = 0xff,
			.segments_left = 0xff,
		},
	};

	switch (item->type) {
	case RTE_FLOW_ITEM_TYPE_ANY:
		mask = &rte_flow_item_any_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_PORT_ID:
		mask = &rte_flow_item_port_id_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_RAW:
		mask = &rte_flow_item_raw_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_ETH:
		mask = &rte_flow_item_eth_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_VLAN:
		mask = &rte_flow_item_vlan_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_IPV4:
		mask = &rte_flow_item_ipv4_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_IPV6:
		mask = &rte_flow_item_ipv6_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_ICMP:
		mask = &rte_flow_item_icmp_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_UDP:
		mask = &rte_flow_item_udp_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_TCP:
		mask = &rte_flow_item_tcp_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_SCTP:
		mask = &rte_flow_item_sctp_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_VXLAN:
		mask = &rte_flow_item_vxlan_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_VXLAN_GPE:
		mask = &rte_flow_item_vxlan_gpe_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_E_TAG:
		mask = &rte_flow_item_e_tag_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_NVGRE:
		mask = &rte_flow_item_nvgre_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_MPLS:
		mask = &rte_flow_item_mpls_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_GRE:
		mask = &rte_flow_item_gre_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_GRE_KEY:
		mask = &gre_key_default_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_META:
		mask = &rte_flow_item_meta_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_RANDOM:
		mask = &rte_flow_item_random_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_FUZZY:
		mask = &rte_flow_item_fuzzy_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_GTP:
		mask = &rte_flow_item_gtp_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_GTP_PSC:
		mask = &rte_flow_item_gtp_psc_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_GENEVE:
		mask = &rte_flow_item_geneve_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_GENEVE_OPT:
		mask = &rte_flow_item_geneve_opt_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_PPPOE_PROTO_ID:
		mask = &rte_flow_item_pppoe_proto_id_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_L2TPV3OIP:
		mask = &rte_flow_item_l2tpv3oip_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_ESP:
		mask = &rte_flow_item_esp_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_AH:
		mask = &rte_flow_item_ah_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_PFCP:
		mask = &rte_flow_item_pfcp_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_PORT_REPRESENTOR:
	case RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT:
		mask = &rte_flow_item_ethdev_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_L2TPV2:
		mask = &rte_flow_item_l2tpv2_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_PPP:
		mask = &rte_flow_item_ppp_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_METER_COLOR:
		mask = &rte_flow_item_meter_color_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_IPV6_ROUTING_EXT:
		mask = &ipv6_routing_ext_default_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_AGGR_AFFINITY:
		mask = &rte_flow_item_aggr_affinity_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_TX_QUEUE:
		mask = &rte_flow_item_tx_queue_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_IB_BTH:
		mask = &rte_flow_item_ib_bth_mask;
		break;
	case RTE_FLOW_ITEM_TYPE_PTYPE:
		mask = &rte_flow_item_ptype_mask;
		break;
	default:
		break;
	}
	return mask;
}

static int
parse_setup_vxlan_encap_data(struct action_vxlan_encap_data *action_vxlan_encap_data)
{
	*action_vxlan_encap_data = (struct action_vxlan_encap_data){
		.conf = (struct rte_flow_action_vxlan_encap){
			.definition = action_vxlan_encap_data->items,
		},
		.items = {
			{
				.type = RTE_FLOW_ITEM_TYPE_ETH,
				.spec = &action_vxlan_encap_data->item_eth,
				.mask = &rte_flow_item_eth_mask,
			},
			{
				.type = RTE_FLOW_ITEM_TYPE_VLAN,
				.spec = &action_vxlan_encap_data->item_vlan,
				.mask = &rte_flow_item_vlan_mask,
			},
			{
				.type = RTE_FLOW_ITEM_TYPE_IPV4,
				.spec = &action_vxlan_encap_data->item_ipv4,
				.mask = &rte_flow_item_ipv4_mask,
			},
			{
				.type = RTE_FLOW_ITEM_TYPE_UDP,
				.spec = &action_vxlan_encap_data->item_udp,
				.mask = &rte_flow_item_udp_mask,
			},
			{
				.type = RTE_FLOW_ITEM_TYPE_VXLAN,
				.spec = &action_vxlan_encap_data->item_vxlan,
				.mask = &rte_flow_item_vxlan_mask,
			},
			{
				.type = RTE_FLOW_ITEM_TYPE_END,
			},
		},
		.item_eth.hdr.ether_type = 0,
		.item_vlan = {
			.hdr.vlan_tci = vxlan_encap_conf.vlan_tci,
			.hdr.eth_proto = 0,
		},
		.item_ipv4.hdr = {
			.src_addr = vxlan_encap_conf.ipv4_src,
			.dst_addr = vxlan_encap_conf.ipv4_dst,
		},
		.item_udp.hdr = {
			.src_port = vxlan_encap_conf.udp_src,
			.dst_port = vxlan_encap_conf.udp_dst,
		},
		.item_vxlan.hdr.flags = 0,
	};
	memcpy(action_vxlan_encap_data->item_eth.hdr.dst_addr.addr_bytes,
	       vxlan_encap_conf.eth_dst, RTE_ETHER_ADDR_LEN);
	memcpy(action_vxlan_encap_data->item_eth.hdr.src_addr.addr_bytes,
	       vxlan_encap_conf.eth_src, RTE_ETHER_ADDR_LEN);
	if (!vxlan_encap_conf.select_ipv4) {
		memcpy(&action_vxlan_encap_data->item_ipv6.hdr.src_addr,
		       &vxlan_encap_conf.ipv6_src,
		       sizeof(vxlan_encap_conf.ipv6_src));
		memcpy(&action_vxlan_encap_data->item_ipv6.hdr.dst_addr,
		       &vxlan_encap_conf.ipv6_dst,
		       sizeof(vxlan_encap_conf.ipv6_dst));
		action_vxlan_encap_data->items[2] = (struct rte_flow_item){
			.type = RTE_FLOW_ITEM_TYPE_IPV6,
			.spec = &action_vxlan_encap_data->item_ipv6,
			.mask = &rte_flow_item_ipv6_mask,
		};
	}
	if (!vxlan_encap_conf.select_vlan)
		action_vxlan_encap_data->items[1].type =
			RTE_FLOW_ITEM_TYPE_VOID;
	if (vxlan_encap_conf.select_tos_ttl) {
		if (vxlan_encap_conf.select_ipv4) {
			static struct rte_flow_item_ipv4 ipv4_mask_tos;

			memcpy(&ipv4_mask_tos, &rte_flow_item_ipv4_mask,
			       sizeof(ipv4_mask_tos));
			ipv4_mask_tos.hdr.type_of_service = 0xff;
			ipv4_mask_tos.hdr.time_to_live = 0xff;
			action_vxlan_encap_data->item_ipv4.hdr.type_of_service =
					vxlan_encap_conf.ip_tos;
			action_vxlan_encap_data->item_ipv4.hdr.time_to_live =
					vxlan_encap_conf.ip_ttl;
			action_vxlan_encap_data->items[2].mask =
							&ipv4_mask_tos;
		} else {
			static struct rte_flow_item_ipv6 ipv6_mask_tos;

			memcpy(&ipv6_mask_tos, &rte_flow_item_ipv6_mask,
			       sizeof(ipv6_mask_tos));
			ipv6_mask_tos.hdr.vtc_flow |=
				RTE_BE32(0xfful << RTE_IPV6_HDR_TC_SHIFT);
			ipv6_mask_tos.hdr.hop_limits = 0xff;
			action_vxlan_encap_data->item_ipv6.hdr.vtc_flow |=
				rte_cpu_to_be_32
					((uint32_t)vxlan_encap_conf.ip_tos <<
					 RTE_IPV6_HDR_TC_SHIFT);
			action_vxlan_encap_data->item_ipv6.hdr.hop_limits =
					vxlan_encap_conf.ip_ttl;
			action_vxlan_encap_data->items[2].mask =
					&ipv6_mask_tos;
		}
	}
	memcpy(action_vxlan_encap_data->item_vxlan.hdr.vni, vxlan_encap_conf.vni,
	       RTE_DIM(vxlan_encap_conf.vni));
	return 0;
}

static int
parse_setup_nvgre_encap_data(struct action_nvgre_encap_data *action_nvgre_encap_data)
{
	memset(action_nvgre_encap_data, 0, sizeof(*action_nvgre_encap_data));
	action_nvgre_encap_data->conf.definition = action_nvgre_encap_data->items;
	action_nvgre_encap_data->items[0] = (struct rte_flow_item){
		.type = RTE_FLOW_ITEM_TYPE_ETH,
		.spec = &action_nvgre_encap_data->item_eth,
		.mask = &rte_flow_item_eth_mask,
	};
	action_nvgre_encap_data->items[1] = (struct rte_flow_item){
		.type = RTE_FLOW_ITEM_TYPE_VLAN,
		.spec = &action_nvgre_encap_data->item_vlan,
		.mask = &rte_flow_item_vlan_mask,
	};
	action_nvgre_encap_data->items[2] = (struct rte_flow_item){
		.type = RTE_FLOW_ITEM_TYPE_IPV4,
		.spec = &action_nvgre_encap_data->item_ipv4,
		.mask = &rte_flow_item_ipv4_mask,
	};
	action_nvgre_encap_data->items[3] = (struct rte_flow_item){
		.type = RTE_FLOW_ITEM_TYPE_NVGRE,
		.spec = &action_nvgre_encap_data->item_nvgre,
		.mask = &rte_flow_item_nvgre_mask,
	};
	action_nvgre_encap_data->items[4] = (struct rte_flow_item){
		.type = RTE_FLOW_ITEM_TYPE_END,
	};
	action_nvgre_encap_data->item_eth.hdr.ether_type = 0;
	action_nvgre_encap_data->item_vlan.hdr.vlan_tci = nvgre_encap_conf.vlan_tci;
	action_nvgre_encap_data->item_vlan.hdr.eth_proto = 0;
	action_nvgre_encap_data->item_ipv4.hdr.src_addr = nvgre_encap_conf.ipv4_src;
	action_nvgre_encap_data->item_ipv4.hdr.dst_addr = nvgre_encap_conf.ipv4_dst;
	memset(&action_nvgre_encap_data->item_nvgre, 0,
	       sizeof(action_nvgre_encap_data->item_nvgre));
	memcpy(action_nvgre_encap_data->item_eth.hdr.dst_addr.addr_bytes,
	       nvgre_encap_conf.eth_dst, RTE_ETHER_ADDR_LEN);
	memcpy(action_nvgre_encap_data->item_eth.hdr.src_addr.addr_bytes,
	       nvgre_encap_conf.eth_src, RTE_ETHER_ADDR_LEN);
	if (!nvgre_encap_conf.select_ipv4) {
		memcpy(&action_nvgre_encap_data->item_ipv6.hdr.src_addr,
		       &nvgre_encap_conf.ipv6_src,
		       sizeof(nvgre_encap_conf.ipv6_src));
		memcpy(&action_nvgre_encap_data->item_ipv6.hdr.dst_addr,
		       &nvgre_encap_conf.ipv6_dst,
		       sizeof(nvgre_encap_conf.ipv6_dst));
		action_nvgre_encap_data->items[2] = (struct rte_flow_item){
			.type = RTE_FLOW_ITEM_TYPE_IPV6,
			.spec = &action_nvgre_encap_data->item_ipv6,
			.mask = &rte_flow_item_ipv6_mask,
		};
	}
	if (!nvgre_encap_conf.select_vlan)
		action_nvgre_encap_data->items[1].type =
			RTE_FLOW_ITEM_TYPE_VOID;
	memcpy(action_nvgre_encap_data->item_nvgre.tni, nvgre_encap_conf.tni,
	       RTE_DIM(nvgre_encap_conf.tni));
	return 0;
}

static void
parser_set_ipv6_ext_remove(uint16_t idx,
			   const struct rte_flow_item pattern[],
			   uint32_t pattern_n, void *userdata)
{
	struct parser_storage *st = parser_storage();
	const struct rte_flow_item_ipv6_ext *ipv6_ext;

	RTE_SET_USED(userdata);
	if (pattern_n != 1 || pattern[0].type != RTE_FLOW_ITEM_TYPE_IPV6_EXT ||
	    pattern[0].spec == NULL || idx >= IPV6_EXT_PUSH_CONFS_MAX_NUM)
		return;
	ipv6_ext = pattern[0].spec;
	st->ipv6_ext_remove_confs[idx].type = ipv6_ext->next_hdr;
}

static void
parser_set_ipv6_ext_push(uint16_t idx,
			 const struct rte_flow_item pattern[],
			 uint32_t pattern_n, void *userdata)
{
	uint32_t i = 0;
	const struct rte_flow_item *item;
	size_t size = 0;
	struct parser_storage *st = parser_storage();
	uint8_t *data = (uint8_t *)&st->ipv6_ext_push_confs[idx].data;
	uint8_t *type = (uint8_t *)&st->ipv6_ext_push_confs[idx].type;
	size_t *total_size = &st->ipv6_ext_push_confs[idx].size;

	RTE_SET_USED(userdata);
	if (idx >= IPV6_EXT_PUSH_CONFS_MAX_NUM)
		return;
	*total_size = 0;
	memset(data, 0x00, ACTION_IPV6_EXT_PUSH_MAX_DATA);
	for (i = pattern_n; i > 0; --i) {
		item = &pattern[i - 1];
		switch (item->type) {
		case RTE_FLOW_ITEM_TYPE_IPV6_EXT:
			if (!item->spec)
				goto error;
			*type =
				((const struct rte_flow_item_ipv6_ext *)item->spec)->next_hdr;
			break;
		case RTE_FLOW_ITEM_TYPE_IPV6_ROUTING_EXT:
		{
			struct rte_flow_item_ipv6_routing_ext ext;
			const struct rte_flow_item_ipv6_routing_ext *spec =
				item->spec;

			if (!spec)
				goto error;
			rte_memcpy(&ext, spec, sizeof(ext));
			if (!ext.hdr.hdr_len) {
				size = sizeof(struct rte_ipv6_routing_ext) +
					(ext.hdr.segments_left << 4);
				ext.hdr.hdr_len = ext.hdr.segments_left << 1;
				if (ext.hdr.type == 4)
					ext.hdr.last_entry =
						ext.hdr.segments_left - 1;
			} else {
				size = sizeof(struct rte_ipv6_routing_ext) +
					(ext.hdr.hdr_len << 3);
			}
			*total_size += size;
			memcpy(data, &ext, size);
			break;
		}
		default:
			goto error;
		}
	}
	RTE_ASSERT((*total_size) <= ACTION_IPV6_EXT_PUSH_MAX_DATA);
	return;
error:
	*total_size = 0;
	memset(data, 0x00, ACTION_IPV6_EXT_PUSH_MAX_DATA);
}

static void
parser_set_sample_actions(uint16_t idx,
			  const struct rte_flow_action actions[],
			  uint32_t actions_n, void *userdata)
{
	uint32_t i;
	struct rte_flow_action *data;
	size_t size;
	uint32_t max_size = sizeof(struct rte_flow_action) *
		ACTION_SAMPLE_ACTIONS_NUM;
	struct parser_storage *st = parser_storage();

	RTE_SET_USED(userdata);
	if (idx >= RAW_SAMPLE_CONFS_MAX_NUM)
		return;
	data = (struct rte_flow_action *)&st->raw_sample_confs[idx].data;
	memset(data, 0x00, max_size);
	for (i = 0; i < actions_n; i++) {
		struct rte_flow_action action = actions[i];
		const struct rte_flow_action_rss *rss;

		if (action.type == RTE_FLOW_ACTION_TYPE_END)
			break;
		switch (action.type) {
		case RTE_FLOW_ACTION_TYPE_MARK:
			size = sizeof(struct rte_flow_action_mark);
			rte_memcpy(&st->sample_mark[idx], action.conf, size);
			action.conf = &st->sample_mark[idx];
			break;
		case RTE_FLOW_ACTION_TYPE_COUNT:
			size = sizeof(struct rte_flow_action_count);
			rte_memcpy(&st->sample_count[idx], action.conf, size);
			action.conf = &st->sample_count[idx];
			break;
		case RTE_FLOW_ACTION_TYPE_QUEUE:
			size = sizeof(struct rte_flow_action_queue);
			rte_memcpy(&st->sample_queue[idx], action.conf, size);
			action.conf = &st->sample_queue[idx];
			break;
		case RTE_FLOW_ACTION_TYPE_RSS:
			size = sizeof(struct rte_flow_action_rss);
			rss = action.conf;
			rte_memcpy(&st->sample_rss_data[idx].conf, rss, size);
			if (rss->key_len && rss->key) {
				st->sample_rss_data[idx].conf.key =
					st->sample_rss_data[idx].key;
				rte_memcpy((void *)(uintptr_t)
					 st->sample_rss_data[idx].conf.key,
					   rss->key,
					   sizeof(uint8_t) * rss->key_len);
			}
			if (rss->queue_num && rss->queue) {
				st->sample_rss_data[idx].conf.queue =
					st->sample_rss_data[idx].queue;
				rte_memcpy((void *)(uintptr_t)
					 st->sample_rss_data[idx].conf.queue,
					   rss->queue,
					   sizeof(uint16_t) * rss->queue_num);
			}
			action.conf = &st->sample_rss_data[idx].conf;
			break;
		case RTE_FLOW_ACTION_TYPE_RAW_ENCAP:
			size = sizeof(struct rte_flow_action_raw_encap);
			rte_memcpy(&st->sample_encap[idx], action.conf, size);
			action.conf = &st->sample_encap[idx];
			break;
		case RTE_FLOW_ACTION_TYPE_PORT_ID:
			size = sizeof(struct rte_flow_action_port_id);
			rte_memcpy(&st->sample_port_id[idx], action.conf, size);
			action.conf = &st->sample_port_id[idx];
			break;
		case RTE_FLOW_ACTION_TYPE_PF:
			break;
		case RTE_FLOW_ACTION_TYPE_VF:
			size = sizeof(struct rte_flow_action_vf);
			rte_memcpy(&st->sample_vf[idx], action.conf, size);
			action.conf = &st->sample_vf[idx];
			break;
		case RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP:
			size = sizeof(struct rte_flow_action_vxlan_encap);
			parse_setup_vxlan_encap_data(&st->sample_vxlan_encap[idx]);
			action.conf = &st->sample_vxlan_encap[idx].conf;
			break;
		case RTE_FLOW_ACTION_TYPE_NVGRE_ENCAP:
			size = sizeof(struct rte_flow_action_nvgre_encap);
			parse_setup_nvgre_encap_data(&st->sample_nvgre_encap[idx]);
			action.conf = &st->sample_nvgre_encap[idx];
			break;
		case RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR:
			size = sizeof(struct rte_flow_action_ethdev);
			rte_memcpy(&st->sample_port_representor[idx],
				   action.conf, size);
			action.conf = &st->sample_port_representor[idx];
			break;
		case RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT:
			size = sizeof(struct rte_flow_action_ethdev);
			rte_memcpy(&st->sample_represented_port[idx],
				   action.conf, size);
			action.conf = &st->sample_represented_port[idx];
			break;
		default:
			fprintf(stderr, "Error - Not supported action\n");
			return;
		}
		*data = action;
		data++;
	}
}

static void
parser_set_raw_common(bool encap, uint16_t idx,
		      const struct rte_flow_item pattern[],
		      uint32_t pattern_n, void *userdata)
{
	uint32_t n = pattern_n;
	int i = 0;
	struct rte_flow_item *item = NULL;
	size_t size = 0;
	uint8_t *data = NULL;
	uint8_t *data_tail = NULL;
	size_t *total_size = NULL;
	uint16_t upper_layer = 0;
	uint16_t proto = 0;
	int gtp_psc = -1;
	const void *src_spec;
	struct rte_flow_item *items =
		(struct rte_flow_item *)(uintptr_t)pattern;
	struct parser_storage *st = parser_storage();

	RTE_SET_USED(userdata);
	if (idx >= RAW_ENCAP_CONFS_MAX_NUM)
		return;
	if (encap) {
		total_size = &st->raw_encap_confs[idx].size;
		data = (uint8_t *)&st->raw_encap_confs[idx].data;
	} else {
		total_size = &st->raw_decap_confs[idx].size;
		data = (uint8_t *)&st->raw_decap_confs[idx].data;
	}
	*total_size = 0;
	memset(data, 0x00, ACTION_RAW_ENCAP_MAX_DATA);
	data_tail = data + ACTION_RAW_ENCAP_MAX_DATA;
	for (i = n - 1; i >= 0; --i) {
		const struct rte_flow_item_gtp *gtp;
		const struct rte_flow_item_geneve_opt *opt;
		struct rte_flow_item_ipv6_routing_ext *ext;

		item = items + i;
		if (item->spec == NULL)
			item->spec = flow_item_default_mask(item);
		src_spec = item->spec;
		switch (item->type) {
		case RTE_FLOW_ITEM_TYPE_ETH:
			size = sizeof(struct rte_ether_hdr);
			break;
		case RTE_FLOW_ITEM_TYPE_VLAN:
			size = sizeof(struct rte_vlan_hdr);
			proto = RTE_ETHER_TYPE_VLAN;
			break;
		case RTE_FLOW_ITEM_TYPE_IPV4:
			size = sizeof(struct rte_ipv4_hdr);
			proto = RTE_ETHER_TYPE_IPV4;
			break;
		case RTE_FLOW_ITEM_TYPE_IPV6:
			size = sizeof(struct rte_ipv6_hdr);
			proto = RTE_ETHER_TYPE_IPV6;
			break;
		case RTE_FLOW_ITEM_TYPE_IPV6_ROUTING_EXT:
			ext = (struct rte_flow_item_ipv6_routing_ext *)(uintptr_t)item->spec;
			if (!ext->hdr.hdr_len) {
				size = sizeof(struct rte_ipv6_routing_ext) +
					(ext->hdr.segments_left << 4);
				ext->hdr.hdr_len = ext->hdr.segments_left << 1;
				if (ext->hdr.type == RTE_IPV6_SRCRT_TYPE_4)
					ext->hdr.last_entry = ext->hdr.segments_left - 1;
			} else {
				size = sizeof(struct rte_ipv6_routing_ext) +
					(ext->hdr.hdr_len << 3);
			}
			proto = IPPROTO_ROUTING;
			break;
		case RTE_FLOW_ITEM_TYPE_UDP:
			size = sizeof(struct rte_udp_hdr);
			proto = 0x11;
			break;
		case RTE_FLOW_ITEM_TYPE_TCP:
			size = sizeof(struct rte_tcp_hdr);
			proto = 0x06;
			break;
		case RTE_FLOW_ITEM_TYPE_VXLAN:
			size = sizeof(struct rte_vxlan_hdr);
			break;
		case RTE_FLOW_ITEM_TYPE_VXLAN_GPE:
			size = sizeof(struct rte_vxlan_gpe_hdr);
			break;
		case RTE_FLOW_ITEM_TYPE_GRE:
			size = sizeof(struct rte_gre_hdr);
			proto = 0x2F;
			break;
		case RTE_FLOW_ITEM_TYPE_GRE_KEY:
			size = sizeof(rte_be32_t);
			proto = 0x0;
			break;
		case RTE_FLOW_ITEM_TYPE_MPLS:
			size = sizeof(struct rte_mpls_hdr);
			proto = 0x0;
			break;
		case RTE_FLOW_ITEM_TYPE_NVGRE:
			size = sizeof(struct rte_flow_item_nvgre);
			proto = 0x2F;
			break;
		case RTE_FLOW_ITEM_TYPE_GENEVE:
			size = sizeof(struct rte_geneve_hdr);
			break;
		case RTE_FLOW_ITEM_TYPE_GENEVE_OPT:
			opt = (const struct rte_flow_item_geneve_opt *)
								item->spec;
			size = offsetof(struct rte_flow_item_geneve_opt,
					option_len) + sizeof(uint8_t);
			if (opt->option_len && opt->data) {
				*total_size += opt->option_len *
					       sizeof(uint32_t);
				rte_memcpy(data_tail - (*total_size),
					   opt->data,
					   opt->option_len * sizeof(uint32_t));
			}
			break;
		case RTE_FLOW_ITEM_TYPE_L2TPV3OIP:
			size = sizeof(rte_be32_t);
			proto = 0x73;
			break;
		case RTE_FLOW_ITEM_TYPE_ESP:
			size = sizeof(struct rte_esp_hdr);
			proto = 0x32;
			break;
		case RTE_FLOW_ITEM_TYPE_AH:
			size = sizeof(struct rte_flow_item_ah);
			proto = 0x33;
			break;
		case RTE_FLOW_ITEM_TYPE_GTP:
			if (gtp_psc < 0) {
				size = sizeof(struct rte_gtp_hdr);
				break;
			}
			if (gtp_psc != i + 1)
				goto error;
			gtp = item->spec;
			if (gtp->hdr.s == 1 || gtp->hdr.pn == 1)
				goto error;
			else {
				struct rte_gtp_hdr_ext_word ext_word = {
					.next_ext = 0x85
				};
				*total_size += sizeof(ext_word);
				rte_memcpy(data_tail - (*total_size),
					   &ext_word, sizeof(ext_word));
			}
			size = sizeof(struct rte_gtp_hdr);
			break;
		case RTE_FLOW_ITEM_TYPE_GTP_PSC:
			if (gtp_psc >= 0)
				goto error;
			else {
				const struct rte_flow_item_gtp_psc *opt = item->spec;
				struct rte_gtp_psc_generic_hdr *hdr;
				size_t hdr_size = RTE_ALIGN(sizeof(*hdr),
							    sizeof(int32_t));

				*total_size += hdr_size;
				hdr = (typeof(hdr))(data_tail - (*total_size));
				memset(hdr, 0, hdr_size);
				if (opt)
					*hdr = opt->hdr;
				hdr->ext_hdr_len = 1;
				gtp_psc = i;
				size = 0;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_PFCP:
			size = sizeof(struct rte_flow_item_pfcp);
			break;
		case RTE_FLOW_ITEM_TYPE_FLEX:
			if (item->spec != NULL) {
				size = ((const struct rte_flow_item_flex *)item->spec)->length;
				src_spec = ((const struct rte_flow_item_flex *)item->spec)->pattern;
			} else {
				size = 0;
				src_spec = NULL;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_GRE_OPTION:
			size = 0;
			if (item->spec) {
				const struct rte_flow_item_gre_opt
					*opt = item->spec;
				if (opt->checksum_rsvd.checksum) {
					*total_size +=
						sizeof(opt->checksum_rsvd);
					rte_memcpy(data_tail - (*total_size),
						   &opt->checksum_rsvd,
						   sizeof(opt->checksum_rsvd));
				}
				if (opt->key.key) {
					*total_size += sizeof(opt->key.key);
					rte_memcpy(data_tail - (*total_size),
						   &opt->key.key,
						   sizeof(opt->key.key));
				}
				if (opt->sequence.sequence) {
					*total_size += sizeof(opt->sequence.sequence);
					rte_memcpy(data_tail - (*total_size),
						   &opt->sequence.sequence,
						   sizeof(opt->sequence.sequence));
				}
			}
			proto = 0x2F;
			break;
		default:
			goto error;
		}
		if (size) {
			*total_size += size;
			rte_memcpy(data_tail - (*total_size), src_spec, size);
			update_fields((data_tail - (*total_size)), item,
				      upper_layer);
			upper_layer = proto;
		}
	}
	RTE_ASSERT((*total_size) <= ACTION_RAW_ENCAP_MAX_DATA);
	memmove(data, (data_tail - (*total_size)), *total_size);
	return;

error:
	*total_size = 0;
	memset(data, 0x00, ACTION_RAW_ENCAP_MAX_DATA);
}

static void
parser_set_raw_encap(uint16_t index, const struct rte_flow_item pattern[],
		     uint32_t pattern_n, void *userdata)
{
	parser_set_raw_common(true, index, pattern, pattern_n, userdata);
}

static void
parser_set_raw_decap(uint16_t index, const struct rte_flow_item pattern[],
		     uint32_t pattern_n, void *userdata)
{
	parser_set_raw_common(false, index, pattern, pattern_n, userdata);
}

static const struct rte_flow_action_raw_encap *
parser_raw_encap_conf_get_cb(uint16_t index, void *userdata)
{
	struct parser_storage *st = parser_storage();

	RTE_SET_USED(userdata);
	if (index >= RAW_ENCAP_CONFS_MAX_NUM)
		return NULL;
	st->raw_encap_conf_cache[index] = (struct rte_flow_action_raw_encap){
		.data = st->raw_encap_confs[index].data,
		.size = st->raw_encap_confs[index].size,
		.preserve = st->raw_encap_confs[index].preserve,
	};
	return &st->raw_encap_conf_cache[index];
}

static const struct rte_flow_action_raw_decap *
parser_raw_decap_conf_get_cb(uint16_t index, void *userdata)
{
	struct parser_storage *st = parser_storage();

	RTE_SET_USED(userdata);
	if (index >= RAW_ENCAP_CONFS_MAX_NUM)
		return NULL;
	st->raw_decap_conf_cache[index] = (struct rte_flow_action_raw_decap){
		.data = st->raw_decap_confs[index].data,
		.size = st->raw_decap_confs[index].size,
	};
	return &st->raw_decap_conf_cache[index];
}

static const struct rte_flow_action_ipv6_ext_push *
parser_ipv6_ext_push_conf_get_cb(uint16_t index, void *userdata)
{
	struct parser_storage *st = parser_storage();

	RTE_SET_USED(userdata);
	if (index >= IPV6_EXT_PUSH_CONFS_MAX_NUM)
		return NULL;
	st->ipv6_ext_push_action_cache[index] =
		(struct rte_flow_action_ipv6_ext_push){
			.data = st->ipv6_ext_push_confs[index].data,
			.size = st->ipv6_ext_push_confs[index].size,
			.type = st->ipv6_ext_push_confs[index].type,
		};
	return &st->ipv6_ext_push_action_cache[index];
}

static const struct rte_flow_action_ipv6_ext_remove *
parser_ipv6_ext_remove_conf_get_cb(uint16_t index, void *userdata)
{
	struct parser_storage *st = parser_storage();

	RTE_SET_USED(userdata);
	if (index >= IPV6_EXT_PUSH_CONFS_MAX_NUM)
		return NULL;
	st->ipv6_ext_remove_action_cache[index] =
		(struct rte_flow_action_ipv6_ext_remove){
			.type = st->ipv6_ext_remove_confs[index].type,
		};
	return &st->ipv6_ext_remove_action_cache[index];
}

static const struct rte_flow_action *
parser_sample_actions_get_cb(uint16_t index, void *userdata)
{
	struct parser_storage *st = parser_storage();

	RTE_SET_USED(userdata);
	if (index >= RAW_SAMPLE_CONFS_MAX_NUM)
		return NULL;
	return st->raw_sample_confs[index].data;
}

static enum print_warning
parser_warning_mode(bool warn)
{
	return warn ? ENABLED_WARN : DISABLED_WARN;
}

static struct rte_port *
parser_port_get(uint16_t port_id)
{
	if (port_id_is_invalid(port_id, DISABLED_WARN) ||
	    port_id == (portid_t)RTE_PORT_ALL)
		return NULL;
	return &ports[port_id];
}

static struct port_flow *
parser_flow_by_index(struct rte_port *port, unsigned int index)
{
	struct port_flow *pf = port->flow_list;

	while (pf && index--)
		pf = pf->next;
	return pf;
}

static struct port_template *
parser_template_by_index(struct port_template *list, unsigned int index)
{
	struct port_template *pt = list;

	while (pt && index--)
		pt = pt->next;
	return pt;
}

static struct port_table *
parser_table_by_index(struct port_table *list, unsigned int index)
{
	struct port_table *pt = list;

	while (pt && index--)
		pt = pt->next;
	return pt;
}

static const struct tunnel_ops *
parser_tunnel_convert(const struct rte_flow_parser_tunnel_ops *src,
		      struct tunnel_ops *dst)
{
	if (!src)
		return NULL;
	memset(dst, 0, sizeof(*dst));
	dst->id = src->id;
	strlcpy(dst->type, src->type, sizeof(dst->type));
	dst->enabled = src->enabled;
	dst->actions = src->actions;
	dst->items = src->items;
	return dst;
}

static int
parser_port_validate(uint16_t port_id, bool warn, void *userdata)
{
	RTE_SET_USED(userdata);
	return port_id_is_invalid(port_id, parser_warning_mode(warn));
}

static uint16_t
parser_flow_rule_count(uint16_t port_id, void *userdata)
{
	struct rte_port *port = parser_port_get(port_id);
	uint16_t count = 0;

	RTE_SET_USED(userdata);
	if (!port)
		return 0;
	for (struct port_flow *pf = port->flow_list; pf; pf = pf->next)
		count++;
	return count;
}

static int
parser_flow_rule_id_get(uint16_t port_id, unsigned int index,
			uint64_t *rule_id, void *userdata)
{
	struct rte_port *port = parser_port_get(port_id);
	struct port_flow *pf;

	RTE_SET_USED(userdata);
	if (!port || !rule_id)
		return -ENOENT;
	pf = parser_flow_by_index(port, index);
	if (!pf)
		return -ENOENT;
	*rule_id = pf->id;
	return 0;
}

static uint16_t
parser_pattern_template_count(uint16_t port_id, void *userdata)
{
	struct rte_port *port = parser_port_get(port_id);
	uint16_t count = 0;

	RTE_SET_USED(userdata);
	if (!port)
		return 0;
	for (struct port_template *pt = port->pattern_templ_list;
	     pt;
	     pt = pt->next)
		count++;
	return count;
}

static int
parser_pattern_template_id_get(uint16_t port_id, unsigned int index,
			       uint32_t *template_id, void *userdata)
{
	struct rte_port *port = parser_port_get(port_id);
	struct port_template *pt;

	RTE_SET_USED(userdata);
	if (!port || !template_id)
		return -ENOENT;
	pt = parser_template_by_index(port->pattern_templ_list, index);
	if (!pt)
		return -ENOENT;
	*template_id = pt->id;
	return 0;
}

static uint16_t
parser_actions_template_count(uint16_t port_id, void *userdata)
{
	struct rte_port *port = parser_port_get(port_id);
	uint16_t count = 0;

	RTE_SET_USED(userdata);
	if (!port)
		return 0;
	for (struct port_template *pt = port->actions_templ_list;
	     pt;
	     pt = pt->next)
		count++;
	return count;
}

static int
parser_actions_template_id_get(uint16_t port_id, unsigned int index,
			       uint32_t *template_id, void *userdata)
{
	struct rte_port *port = parser_port_get(port_id);
	struct port_template *pt;

	RTE_SET_USED(userdata);
	if (!port || !template_id)
		return -ENOENT;
	pt = parser_template_by_index(port->actions_templ_list, index);
	if (!pt)
		return -ENOENT;
	*template_id = pt->id;
	return 0;
}

static uint16_t
parser_table_count(uint16_t port_id, void *userdata)
{
	struct rte_port *port = parser_port_get(port_id);
	uint16_t count = 0;

	RTE_SET_USED(userdata);
	if (!port)
		return 0;
	for (struct port_table *pt = port->table_list; pt; pt = pt->next)
		count++;
	return count;
}

static int
parser_table_id_get(uint16_t port_id, unsigned int index,
		    uint32_t *table_id, void *userdata)
{
	struct rte_port *port = parser_port_get(port_id);
	struct port_table *pt;

	RTE_SET_USED(userdata);
	if (!port || !table_id)
		return -ENOENT;
	pt = parser_table_by_index(port->table_list, index);
	if (!pt)
		return -ENOENT;
	*table_id = pt->id;
	return 0;
}

static uint16_t
parser_queue_count(uint16_t port_id, void *userdata)
{
	struct rte_port *port = parser_port_get(port_id);

	RTE_SET_USED(userdata);
	if (!port)
		return 0;
	return port->queue_nb;
}

static uint16_t
parser_rss_queue_count(uint16_t port_id, void *userdata)
{
	struct rte_port *port = parser_port_get(port_id);

	RTE_SET_USED(userdata);
	if (!port)
		return 0;
	return port->queue_nb ? port->queue_nb : port->dev_info.max_rx_queues;
}

static struct rte_flow_template_table *
parser_table_get(uint16_t port_id, uint32_t table_id, void *userdata)
{
	struct rte_port *port = parser_port_get(port_id);
	struct port_table *pt;

	RTE_SET_USED(userdata);
	if (!port)
		return NULL;
	for (pt = port->table_list; pt; pt = pt->next)
		if (pt->id == table_id)
			return pt->table;
	return NULL;
}

static struct rte_flow_action_handle *
parser_action_handle_get(uint16_t port_id, uint32_t action_id, void *userdata)
{
	RTE_SET_USED(userdata);
	return port_action_handle_get_by_id(port_id, action_id);
}

static struct rte_flow_meter_profile *
parser_meter_profile_get(uint16_t port_id, uint32_t profile_id, void *userdata)
{
	RTE_SET_USED(userdata);
	return port_meter_profile_get_by_id(port_id, profile_id);
}

static struct rte_flow_meter_policy *
parser_meter_policy_get(uint16_t port_id, uint32_t policy_id, void *userdata)
{
	RTE_SET_USED(userdata);
	return port_meter_policy_get_by_id(port_id, policy_id);
}

static struct rte_flow_item_flex_handle *
parser_flex_handle_get(uint16_t port_id, uint16_t flex_id, void *userdata)
{
	struct flex_item *fp;

	RTE_SET_USED(userdata);
	if (port_id >= RTE_MAX_ETHPORTS || flex_id >= FLEX_MAX_PARSERS_NUM)
		return NULL;
	fp = flex_items[port_id][flex_id];
	return fp ? fp->flex_handle : NULL;
}

static int
parser_flex_pattern_get(uint16_t pattern_id,
			const struct rte_flow_item_flex **spec,
			const struct rte_flow_item_flex **mask,
			void *userdata)
{
	RTE_SET_USED(userdata);
	if (pattern_id >= FLEX_MAX_PATTERNS_NUM || !spec || !mask)
		return -ENOENT;
	*spec = &flex_patterns[pattern_id].spec;
	*mask = &flex_patterns[pattern_id].mask;
	return 0;
}

static uint16_t
parser_verbose_level_get(void *userdata)
{
	RTE_SET_USED(userdata);
	return verbose_level;
}

static void
parser_queue_group_set_miss_actions(uint16_t port_id,
				    const struct rte_flow_attr *attr,
				    const struct rte_flow_action actions[],
				    void *userdata)
{
	RTE_SET_USED(userdata);
	port_queue_group_set_miss_actions(port_id, attr, actions);
}

static void
parser_flow_get_info(uint16_t port_id, void *userdata)
{
	RTE_SET_USED(userdata);
	port_flow_get_info(port_id);
}

static void
parser_flow_configure(uint16_t port_id,
		      const struct rte_flow_port_attr *port_attr,
		      uint32_t nb_queue,
		      const struct rte_flow_queue_attr *queue_attr,
		      void *userdata)
{
	RTE_SET_USED(userdata);
	port_flow_configure(port_id, port_attr, (uint16_t)nb_queue, queue_attr);
}

static void
parser_flow_pattern_template_create(uint16_t port_id, uint32_t id,
				    const struct rte_flow_pattern_template_attr *attr,
				    const struct rte_flow_item pattern[],
				    void *userdata)
{
	RTE_SET_USED(userdata);
	port_flow_pattern_template_create(port_id, id, attr, pattern);
}

static void
parser_flow_pattern_template_destroy(uint16_t port_id,
				     uint32_t nb_id,
				     const uint32_t id[],
				     void *userdata)
{
	RTE_SET_USED(userdata);
	port_flow_pattern_template_destroy(port_id, nb_id, id);
}

static void
parser_flow_actions_template_create(uint16_t port_id, uint32_t id,
				    const struct rte_flow_actions_template_attr *attr,
				    const struct rte_flow_action actions[],
				    const struct rte_flow_action masks[],
				    void *userdata)
{
	RTE_SET_USED(userdata);
	port_flow_actions_template_create(port_id, id, attr, actions, masks);
}

static void
parser_flow_actions_template_destroy(uint16_t port_id,
				     uint32_t nb_id,
				     const uint32_t id[],
				     void *userdata)
{
	RTE_SET_USED(userdata);
	port_flow_actions_template_destroy(port_id, nb_id, id);
}

static void
parser_flow_template_table_create(uint16_t port_id, uint32_t table_id,
				  const struct rte_flow_template_table_attr *attr,
				  uint32_t nb_pattern,
				  const uint32_t pattern_id[],
				  uint32_t nb_action,
				  const uint32_t action_id[],
				  void *userdata)
{
	uint32_t *pat = NULL;
	uint32_t *act = NULL;

	RTE_SET_USED(userdata);
	pat = nb_pattern ? malloc(sizeof(*pat) * nb_pattern) : NULL;
	act = nb_action ? malloc(sizeof(*act) * nb_action) : NULL;
	if ((nb_pattern && !pat) || (nb_action && !act))
		goto out;
	for (uint32_t i = 0; i < nb_pattern; ++i)
		pat[i] = pattern_id[i];
	for (uint32_t i = 0; i < nb_action; ++i)
		act[i] = action_id[i];
	port_flow_template_table_create(port_id, table_id, attr,
					nb_pattern, pat, nb_action, act);
out:
	free(pat);
	free(act);
}

static void
parser_flow_template_table_destroy(uint16_t port_id,
				   uint32_t nb_id,
				   const uint32_t id[],
				   void *userdata)
{
	RTE_SET_USED(userdata);
	port_flow_template_table_destroy(port_id, nb_id, id);
}

static void
parser_flow_template_table_resize_complete(uint16_t port_id,
					   uint32_t table_id,
					   void *userdata)
{
	RTE_SET_USED(userdata);
	port_flow_template_table_resize_complete(port_id, table_id);
}

static void
parser_flow_template_table_resize(uint16_t port_id, uint32_t table_id,
				  uint32_t nb_rules, void *userdata)
{
	RTE_SET_USED(userdata);
	port_flow_template_table_resize(port_id, table_id, nb_rules);
}

static void
parser_queue_flow_create(uint16_t port_id, uint16_t queue, bool postpone,
			 uint32_t table_id, uint32_t rule_id,
			 uint32_t pattern_id, uint32_t action_id,
			 const struct rte_flow_item pattern[],
			 const struct rte_flow_action actions[],
			 void *userdata)
{
	RTE_SET_USED(userdata);
	port_queue_flow_create(port_id, queue, postpone, table_id, rule_id,
			       pattern_id, action_id, pattern, actions);
}

static void
parser_queue_flow_destroy(uint16_t port_id, uint16_t queue, bool postpone,
			  uint32_t rule_n, const uint64_t rule[],
			  bool is_user_id, void *userdata)
{
	RTE_SET_USED(userdata);
	port_queue_flow_destroy(port_id, queue, postpone, rule_n, rule);
	RTE_SET_USED(is_user_id);
}

static void
parser_queue_flow_update_resized(uint16_t port_id, uint16_t queue,
				 bool postpone, uint64_t rule_id,
				 void *userdata)
{
	RTE_SET_USED(userdata);
	port_queue_flow_update_resized(port_id, queue, postpone,
				       (uint32_t)rule_id);
}

static void
parser_queue_flow_update(uint16_t port_id, uint16_t queue, bool postpone,
			 uint32_t rule_id, uint32_t action_id,
			 const struct rte_flow_action actions[],
			 void *userdata)
{
	RTE_SET_USED(userdata);
	port_queue_flow_update(port_id, queue, postpone, rule_id,
			       action_id, actions);
}

static void
parser_queue_flow_push(uint16_t port_id, uint16_t queue, void *userdata)
{
	RTE_SET_USED(userdata);
	port_queue_flow_push(port_id, queue);
}

static void
parser_queue_flow_pull(uint16_t port_id, uint16_t queue, void *userdata)
{
	RTE_SET_USED(userdata);
	port_queue_flow_pull(port_id, queue);
}

static void
parser_flow_hash_calc(uint16_t port_id, uint32_t table_id,
		      uint32_t pattern_id,
		      const struct rte_flow_item pattern[],
		      void *userdata)
{
	RTE_SET_USED(userdata);
	port_flow_hash_calc(port_id, table_id,
			    (uint8_t)pattern_id, pattern);
}

static void
parser_flow_hash_calc_encap(uint16_t port_id,
			    enum rte_flow_encap_hash_field field,
			    const struct rte_flow_item pattern[],
			    void *userdata)
{
	RTE_SET_USED(userdata);
	port_flow_hash_calc_encap(port_id, field, pattern);
}

static void
parser_queue_flow_aged(uint16_t port_id, uint16_t queue,
		       bool destroy, void *userdata)
{
	RTE_SET_USED(userdata);
	port_queue_flow_aged(port_id, queue, destroy ? 1 : 0);
}

static void
parser_queue_action_handle_create(uint16_t port_id, uint16_t queue,
				  bool postpone, uint32_t group, bool is_list,
				  const struct rte_flow_indir_action_conf *conf,
				  const struct rte_flow_action actions[],
				  void *userdata)
{
	RTE_SET_USED(userdata);
	port_queue_action_handle_create(port_id, queue, postpone, group,
					is_list, conf, actions);
}

static void
parser_queue_action_handle_destroy(uint16_t port_id, uint16_t queue,
				   bool postpone, uint32_t nb_id,
				   const uint32_t id[],
				   void *userdata)
{
	RTE_SET_USED(userdata);
	port_queue_action_handle_destroy(port_id, queue, postpone, nb_id, id);
}

static void
parser_queue_action_handle_update(uint16_t port_id, uint16_t queue,
				  bool postpone, uint32_t group,
				  const struct rte_flow_action actions[],
				  void *userdata)
{
	RTE_SET_USED(userdata);
	port_queue_action_handle_update(port_id, queue, postpone, group,
					actions);
}

static void
parser_queue_action_handle_query(uint16_t port_id, uint16_t queue,
				 bool postpone, uint32_t action_id,
				 void *userdata)
{
	RTE_SET_USED(userdata);
	port_queue_action_handle_query(port_id, queue, postpone, action_id);
}

static void
parser_queue_action_handle_query_update(uint16_t port_id, uint16_t queue,
					bool postpone, uint32_t action_id,
					enum rte_flow_query_update_mode qu_mode,
					struct rte_flow_action actions[],
					void *userdata)
{
	RTE_SET_USED(userdata);
	port_queue_action_handle_query_update(port_id, queue, postpone,
					      action_id, qu_mode, actions);
}

static void
parser_action_handle_create(uint16_t port_id, uint32_t group,
			    bool is_list,
			    const struct rte_flow_indir_action_conf *conf,
			    const struct rte_flow_action actions[],
			    void *userdata)
{
	RTE_SET_USED(userdata);
	port_action_handle_create(port_id, group, is_list, conf, actions);
}

static void
parser_action_handle_destroy(uint16_t port_id, uint32_t nb_id,
			     const uint32_t id[], void *userdata)
{
	RTE_SET_USED(userdata);
	port_action_handle_destroy(port_id, nb_id, id);
}

static void
parser_action_handle_update(uint16_t port_id, uint32_t group,
			    const struct rte_flow_action actions[],
			    void *userdata)
{
	RTE_SET_USED(userdata);
	port_action_handle_update(port_id, group, actions);
}

static void
parser_action_handle_query(uint16_t port_id, uint32_t action_id,
			   void *userdata)
{
	RTE_SET_USED(userdata);
	port_action_handle_query(port_id, action_id);
}

static void
parser_action_handle_query_update(uint16_t port_id, uint32_t action_id,
				  enum rte_flow_query_update_mode qu_mode,
				  struct rte_flow_action actions[],
				  void *userdata)
{
	RTE_SET_USED(userdata);
	port_action_handle_query_update(port_id, action_id, qu_mode, actions);
}

static void
parser_flow_validate(uint16_t port_id, const struct rte_flow_attr *attr,
		     const struct rte_flow_item pattern[],
		     const struct rte_flow_action actions[],
		     const struct rte_flow_parser_tunnel_ops *tunnel_ops,
		     void *userdata)
{
	struct tunnel_ops ops;

	RTE_SET_USED(userdata);
	port_flow_validate(port_id, attr, pattern, actions,
			   tunnel_ops ? parser_tunnel_convert(tunnel_ops, &ops)
				      : NULL);
}

static void
parser_flow_create(uint16_t port_id, const struct rte_flow_attr *attr,
		   const struct rte_flow_item pattern[],
		   const struct rte_flow_action actions[],
		   const struct rte_flow_parser_tunnel_ops *tunnel_ops,
		   uintptr_t user_id, void *userdata)
{
	struct tunnel_ops ops;

	RTE_SET_USED(userdata);
	port_flow_create(port_id, attr, pattern, actions,
			 tunnel_ops ? parser_tunnel_convert(tunnel_ops, &ops)
				    : NULL,
			 user_id);
}

static void
parser_flow_destroy(uint16_t port_id, uint32_t nb_rule, const uint64_t rule[],
		    bool is_user_id, void *userdata)
{
	RTE_SET_USED(userdata);
	port_flow_destroy(port_id, nb_rule, rule, is_user_id);
}

static void
parser_flow_update(uint16_t port_id, uint32_t rule_id,
		   const struct rte_flow_action actions[],
		   uintptr_t user_id, void *userdata)
{
	RTE_SET_USED(userdata);
	port_flow_update(port_id, rule_id, actions, user_id != 0);
}

static void
parser_flow_flush(uint16_t port_id, void *userdata)
{
	RTE_SET_USED(userdata);
	port_flow_flush(port_id);
}

static void
parser_flow_dump(uint16_t port_id, bool all, uint64_t rule, const char *file,
		 bool is_user_id, void *userdata)
{
	RTE_SET_USED(userdata);
	port_flow_dump(port_id, all, rule, file, is_user_id);
}

static void
parser_flow_query(uint16_t port_id, uint64_t rule,
		  struct rte_flow_action *action, bool is_user_id,
		  void *userdata)
{
	RTE_SET_USED(userdata);
	port_flow_query(port_id, rule, action, is_user_id);
}

static void
parser_flow_list(uint16_t port_id, uint32_t group_n, const uint32_t group[],
		 void *userdata)
{
	RTE_SET_USED(userdata);
	port_flow_list(port_id, group_n, group);
}

static void
parser_flow_isolate(uint16_t port_id, int set, void *userdata)
{
	RTE_SET_USED(userdata);
	port_flow_isolate(port_id, set);
}

static void
parser_flow_aged(uint16_t port_id, int destroy, void *userdata)
{
	RTE_SET_USED(userdata);
	port_flow_aged(port_id, destroy);
}

static void
parser_flow_tunnel_create(uint16_t port_id,
			  const struct rte_flow_parser_tunnel_ops *ops_cfg,
			  void *userdata)
{
	struct tunnel_ops ops;

	RTE_SET_USED(userdata);
	port_flow_tunnel_create(port_id,
				ops_cfg ? parser_tunnel_convert(ops_cfg, &ops)
					: NULL);
}

static void
parser_flow_tunnel_destroy(uint16_t port_id, uint32_t id, void *userdata)
{
	RTE_SET_USED(userdata);
	port_flow_tunnel_destroy(port_id, id);
}

static void
parser_flow_tunnel_list(uint16_t port_id, void *userdata)
{
	RTE_SET_USED(userdata);
	port_flow_tunnel_list(port_id);
}

static void
parser_meter_policy_add(uint16_t port_id, uint32_t policy_id,
			const struct rte_flow_action actions[],
			void *userdata)
{
	RTE_SET_USED(userdata);
	port_meter_policy_add(port_id, policy_id, actions);
}

static void
parser_flex_item_create(uint16_t port_id, uint16_t token,
			const char *filename, void *userdata)
{
	RTE_SET_USED(userdata);
	flex_item_create(port_id, token, filename);
}

static void
parser_flex_item_destroy(uint16_t port_id, uint16_t token, void *userdata)
{
	RTE_SET_USED(userdata);
	flex_item_destroy(port_id, token);
}

static const struct rte_flow_parser_query_ops parser_query_ops = {
	.port_validate = parser_port_validate,
	.flow_rule_count = parser_flow_rule_count,
	.flow_rule_id_get = parser_flow_rule_id_get,
	.pattern_template_count = parser_pattern_template_count,
	.pattern_template_id_get = parser_pattern_template_id_get,
	.actions_template_count = parser_actions_template_count,
	.actions_template_id_get = parser_actions_template_id_get,
	.table_count = parser_table_count,
	.table_id_get = parser_table_id_get,
	.queue_count = parser_queue_count,
	.rss_queue_count = parser_rss_queue_count,
	.table_get = parser_table_get,
	.action_handle_get = parser_action_handle_get,
	.meter_profile_get = parser_meter_profile_get,
	.meter_policy_get = parser_meter_policy_get,
	.raw_encap_conf_get = parser_raw_encap_conf_get_cb,
	.raw_decap_conf_get = parser_raw_decap_conf_get_cb,
	.ipv6_ext_push_conf_get = parser_ipv6_ext_push_conf_get_cb,
	.ipv6_ext_remove_conf_get = parser_ipv6_ext_remove_conf_get_cb,
	.sample_actions_get = parser_sample_actions_get_cb,
	.verbose_level_get = parser_verbose_level_get,
	.flex_handle_get = parser_flex_handle_get,
	.flex_pattern_get = parser_flex_pattern_get,
};

static const struct rte_flow_parser_command_ops parser_command_ops = {
	.flow_get_info = parser_flow_get_info,
	.flow_configure = parser_flow_configure,
	.flow_pattern_template_create = parser_flow_pattern_template_create,
	.flow_pattern_template_destroy = parser_flow_pattern_template_destroy,
	.flow_actions_template_create = parser_flow_actions_template_create,
	.flow_actions_template_destroy = parser_flow_actions_template_destroy,
	.flow_template_table_create = parser_flow_template_table_create,
	.flow_template_table_destroy = parser_flow_template_table_destroy,
	.flow_template_table_resize_complete =
		parser_flow_template_table_resize_complete,
	.queue_group_set_miss_actions = parser_queue_group_set_miss_actions,
	.flow_template_table_resize = parser_flow_template_table_resize,
	.queue_flow_create = parser_queue_flow_create,
	.queue_flow_destroy = parser_queue_flow_destroy,
	.queue_flow_update_resized = parser_queue_flow_update_resized,
	.queue_flow_update = parser_queue_flow_update,
	.queue_flow_push = parser_queue_flow_push,
	.queue_flow_pull = parser_queue_flow_pull,
	.flow_hash_calc = parser_flow_hash_calc,
	.flow_hash_calc_encap = parser_flow_hash_calc_encap,
	.queue_flow_aged = parser_queue_flow_aged,
	.queue_action_handle_create = parser_queue_action_handle_create,
	.queue_action_handle_destroy = parser_queue_action_handle_destroy,
	.queue_action_handle_update = parser_queue_action_handle_update,
	.queue_action_handle_query = parser_queue_action_handle_query,
	.queue_action_handle_query_update =
		parser_queue_action_handle_query_update,
	.action_handle_create = parser_action_handle_create,
	.action_handle_destroy = parser_action_handle_destroy,
	.action_handle_update = parser_action_handle_update,
	.action_handle_query = parser_action_handle_query,
	.action_handle_query_update = parser_action_handle_query_update,
	.flow_validate = parser_flow_validate,
	.flow_create = parser_flow_create,
	.flow_destroy = parser_flow_destroy,
	.flow_update = parser_flow_update,
	.flow_flush = parser_flow_flush,
	.flow_dump = parser_flow_dump,
	.flow_query = parser_flow_query,
	.flow_list = parser_flow_list,
	.flow_isolate = parser_flow_isolate,
	.flow_aged = parser_flow_aged,
	.flow_tunnel_create = parser_flow_tunnel_create,
	.flow_tunnel_destroy = parser_flow_tunnel_destroy,
	.flow_tunnel_list = parser_flow_tunnel_list,
	.meter_policy_add = parser_meter_policy_add,
	.flex_item_create = parser_flex_item_create,
	.flex_item_destroy = parser_flex_item_destroy,
	.set_raw_encap = parser_set_raw_encap,
	.set_raw_decap = parser_set_raw_decap,
	.set_sample_actions = parser_set_sample_actions,
	.set_ipv6_ext_push = parser_set_ipv6_ext_push,
	.set_ipv6_ext_remove = parser_set_ipv6_ext_remove,
};

static const struct rte_flow_parser_ops parser_ops = {
	.query = &parser_query_ops,
	.command = &parser_command_ops,
};

int
testpmd_flow_parser_init(void)
{
	flow_parser_reset_defaults();
	return rte_flow_parser_set_default_ops(&parser_ops, NULL);
}

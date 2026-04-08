/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2016 6WIND S.A.
 * Copyright 2016 Mellanox Technologies, Ltd
 * Copyright 2026 DynaNIC Semiconductors, Ltd.
 */

#include <stdio.h>
#include <string.h>

#include <cmdline_parse.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_num.h>
#include <rte_hexdump.h>

#include <rte_flow_parser_cmdline.h>

#include "testpmd.h"

/*
 * Dynamic token callbacks and cmdline protocol handling live in
 * librte_ethdev (rte_flow_parser_cmd_flow_cb / _set_raw_cb).
 * testpmd only provides the dispatch function and cmdline instances.
 */

/* Application-owned flow parser configuration storage */
struct rte_flow_parser_vxlan_encap_conf testpmd_vxlan_conf;
struct rte_flow_parser_nvgre_encap_conf testpmd_nvgre_conf;
struct rte_flow_parser_l2_encap_conf testpmd_l2_encap_conf;
struct rte_flow_parser_l2_decap_conf testpmd_l2_decap_conf;
struct rte_flow_parser_mplsogre_encap_conf testpmd_mplsogre_encap_conf;
struct rte_flow_parser_mplsogre_decap_conf testpmd_mplsogre_decap_conf;
struct rte_flow_parser_mplsoudp_encap_conf testpmd_mplsoudp_encap_conf;
struct rte_flow_parser_mplsoudp_decap_conf testpmd_mplsoudp_decap_conf;
struct rte_flow_action_conntrack testpmd_conntrack;

static struct rte_flow_parser_raw_encap_data testpmd_raw_encap[RAW_ENCAP_CONFS_MAX_NUM];
static struct rte_flow_parser_raw_decap_data testpmd_raw_decap[RAW_ENCAP_CONFS_MAX_NUM];
static struct rte_flow_parser_ipv6_ext_push_data testpmd_ipv6_push[IPV6_EXT_PUSH_CONFS_MAX_NUM];
static struct rte_flow_parser_ipv6_ext_remove_data testpmd_ipv6_remove[IPV6_EXT_PUSH_CONFS_MAX_NUM];
static struct rte_flow_parser_sample_slot testpmd_sample[RAW_SAMPLE_CONFS_MAX_NUM];

void
testpmd_flow_parser_config_init(void)
{
	/* VXLAN defaults: IPv4, standard port, placeholder addresses */
	testpmd_vxlan_conf = (struct rte_flow_parser_vxlan_encap_conf){
		.select_ipv4 = 1,
		.udp_dst = RTE_BE16(RTE_VXLAN_DEFAULT_PORT),
		.ipv4_src = RTE_IPV4(127, 0, 0, 1),
		.ipv4_dst = RTE_IPV4(255, 255, 255, 255),
		.ipv6_src = RTE_IPV6_ADDR_LOOPBACK,
		.ipv6_dst = RTE_IPV6(0, 0, 0, 0, 0, 0, 0, 0x1111),
		.ip_ttl = 255,
		.eth_dst = { .addr_bytes = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
	};
	/* NVGRE defaults: IPv4, placeholder addresses */
	testpmd_nvgre_conf = (struct rte_flow_parser_nvgre_encap_conf){
		.select_ipv4 = 1,
		.ipv4_src = RTE_IPV4(127, 0, 0, 1),
		.ipv4_dst = RTE_IPV4(255, 255, 255, 255),
		.ipv6_src = RTE_IPV6_ADDR_LOOPBACK,
		.ipv6_dst = RTE_IPV6(0, 0, 0, 0, 0, 0, 0, 0x1111),
		.eth_dst = { .addr_bytes = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
	};

	struct rte_flow_parser_config cfg = {
		.vxlan_encap = &testpmd_vxlan_conf,
		.nvgre_encap = &testpmd_nvgre_conf,
		.l2_encap = &testpmd_l2_encap_conf,
		.l2_decap = &testpmd_l2_decap_conf,
		.mplsogre_encap = &testpmd_mplsogre_encap_conf,
		.mplsogre_decap = &testpmd_mplsogre_decap_conf,
		.mplsoudp_encap = &testpmd_mplsoudp_encap_conf,
		.mplsoudp_decap = &testpmd_mplsoudp_decap_conf,
		.conntrack = &testpmd_conntrack,
		.raw_encap = { testpmd_raw_encap, RAW_ENCAP_CONFS_MAX_NUM },
		.raw_decap = { testpmd_raw_decap, RAW_ENCAP_CONFS_MAX_NUM },
		.ipv6_ext_push = { testpmd_ipv6_push, IPV6_EXT_PUSH_CONFS_MAX_NUM },
		.ipv6_ext_remove = { testpmd_ipv6_remove, IPV6_EXT_PUSH_CONFS_MAX_NUM },
		.sample = { testpmd_sample, RAW_SAMPLE_CONFS_MAX_NUM },
	};
	rte_flow_parser_config_register(&cfg);
}

/* show raw_encap/raw_decap support */
struct cmd_show_set_raw_result {
	cmdline_fixed_string_t cmd_show;
	cmdline_fixed_string_t cmd_what;
	cmdline_fixed_string_t cmd_all;
	uint16_t cmd_index;
};

static void
cmd_show_set_raw_parsed(void *parsed_result, struct cmdline *cl, void *data)
{
	struct cmd_show_set_raw_result *res = parsed_result;
	uint16_t index = res->cmd_index;
	const uint8_t *raw_data = NULL;
	size_t raw_size = 0;
	char title[16] = { 0 };
	int all = 0;

	RTE_SET_USED(cl);
	RTE_SET_USED(data);
	if (strcmp(res->cmd_all, "all") == 0) {
		all = 1;
		index = 0;
	} else if (index >= RAW_ENCAP_CONFS_MAX_NUM) {
		fprintf(stderr, "index should be 0-%u\n",
			RAW_ENCAP_CONFS_MAX_NUM - 1);
		return;
	}
	do {
		if (strcmp(res->cmd_what, "raw_encap") == 0) {
			const struct rte_flow_action_raw_encap *conf =
				rte_flow_parser_raw_encap_conf(index);

			if (conf == NULL || conf->data == NULL || conf->size == 0) {
				fprintf(stderr,
					"raw_encap %u not configured\n",
					index);
				goto next;
			}
			raw_data = conf->data;
			raw_size = conf->size;
		} else if (strcmp(res->cmd_what, "raw_decap") == 0) {
			const struct rte_flow_action_raw_decap *conf =
				rte_flow_parser_raw_decap_conf(index);

			if (conf == NULL || conf->data == NULL || conf->size == 0) {
				fprintf(stderr,
					"raw_decap %u not configured\n",
					index);
				goto next;
			}
			raw_data = conf->data;
			raw_size = conf->size;
		}
		snprintf(title, sizeof(title), "\nindex: %u", index);
		rte_hexdump(stdout, title, raw_data, raw_size);
next:
		raw_data = NULL;
		raw_size = 0;
	} while (all && ++index < RAW_ENCAP_CONFS_MAX_NUM);
}

static cmdline_parse_token_string_t cmd_show_set_raw_cmd_show =
	TOKEN_STRING_INITIALIZER(struct cmd_show_set_raw_result,
			cmd_show, "show");
static cmdline_parse_token_string_t cmd_show_set_raw_cmd_what =
	TOKEN_STRING_INITIALIZER(struct cmd_show_set_raw_result,
			cmd_what, "raw_encap#raw_decap");
static cmdline_parse_token_num_t cmd_show_set_raw_cmd_index =
	TOKEN_NUM_INITIALIZER(struct cmd_show_set_raw_result,
			cmd_index, RTE_UINT16);
static cmdline_parse_token_string_t cmd_show_set_raw_cmd_all =
	TOKEN_STRING_INITIALIZER(struct cmd_show_set_raw_result,
			cmd_all, "all");

cmdline_parse_inst_t cmd_flow = {
	.f = rte_flow_parser_cmd_flow_cb,
	.data = NULL,
	.help_str = NULL,
	.tokens = {
		NULL,
	},
};

cmdline_parse_inst_t cmd_set_raw = {
	.f = rte_flow_parser_cmd_set_raw_cb,
	.data = NULL,
	.help_str = NULL,
	.tokens = {
		NULL,
	},
};

cmdline_parse_inst_t cmd_show_set_raw = {
	.f = cmd_show_set_raw_parsed,
	.data = NULL,
	.help_str = "show <raw_encap|raw_decap> <index>",
	.tokens = {
		(void *)&cmd_show_set_raw_cmd_show,
		(void *)&cmd_show_set_raw_cmd_what,
		(void *)&cmd_show_set_raw_cmd_index,
		NULL,
	},
};

cmdline_parse_inst_t cmd_show_set_raw_all = {
	.f = cmd_show_set_raw_parsed,
	.data = NULL,
	.help_str = "show <raw_encap|raw_decap> all",
	.tokens = {
		(void *)&cmd_show_set_raw_cmd_show,
		(void *)&cmd_show_set_raw_cmd_what,
		(void *)&cmd_show_set_raw_cmd_all,
		NULL,
	},
};

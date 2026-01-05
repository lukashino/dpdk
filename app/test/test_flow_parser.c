/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdint.h>
#include <string.h>

#include <rte_flow_parser.h>

#include "test.h"

static int
test_flow_parser_command_mapping(void)
{
	static const char *create_cmd =
		"flow create 0 ingress pattern eth / end "
		"actions drop / end";
	static const char *list_cmd = "flow list 0";
	uint8_t outbuf[4096];
	struct rte_flow_parser_output *out = (void *)outbuf;
	int ret;

	ret = rte_flow_parser_init(NULL, NULL);
	if (ret != 0)
		return TEST_FAILED;

	memset(outbuf, 0, sizeof(outbuf));
	ret = rte_flow_parser_parse(create_cmd, out, sizeof(outbuf));
	if (ret != 0 ||
	    out->command != RTE_FLOW_PARSER_CMD_CREATE ||
	    out->port != 0 ||
	    out->args.vc.pattern_n == 0 ||
	    out->args.vc.actions_n == 0) {
		return TEST_FAILED;
	}

	memset(outbuf, 0, sizeof(outbuf));
	ret = rte_flow_parser_parse(list_cmd, out, sizeof(outbuf));
	if (ret != 0 ||
	    out->command != RTE_FLOW_PARSER_CMD_LIST ||
	    out->port != 0)
		return TEST_FAILED;

	return TEST_SUCCESS;
}

static int
test_flow_parser_lightweight_helpers(void)
{
	const struct rte_flow_item *pattern = NULL;
	const struct rte_flow_action *actions = NULL;
	struct rte_flow_attr attr;
	uint32_t pattern_n = 0;
	uint32_t actions_n = 0;
	int ret;

	ret = rte_flow_parser_parse_attr_str("ingress group 1", &attr);
	if (ret != 0 || attr.group != 1 || attr.ingress != 1)
		return TEST_FAILED;

	ret = rte_flow_parser_parse_pattern_str("eth / ipv4 / end",
						&pattern, &pattern_n);
	if (ret != 0 || pattern_n == 0 ||
	    pattern[0].type != RTE_FLOW_ITEM_TYPE_ETH)
		return TEST_FAILED;

	ret = rte_flow_parser_parse_actions_str("queue index 3 / end",
						&actions, &actions_n);
	if (ret != 0 || actions_n == 0 ||
	    actions[0].type != RTE_FLOW_ACTION_TYPE_QUEUE)
		return TEST_FAILED;

	return TEST_SUCCESS;
}

REGISTER_TEST_COMMAND(flow_parser_autotest,
		      test_flow_parser_command_mapping);

REGISTER_TEST_COMMAND(flow_parser_helpers_autotest,
		      test_flow_parser_lightweight_helpers);

/* SPDX-License-Identifier: BSD-3-Clause */

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_eal.h>
#include <rte_flow.h>
#include <rte_ip.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static uint32_t
ipv4_to_be32(const char *addr)
{
	struct in_addr v4;
	if (inet_pton(AF_INET, addr, &v4) != 1)
		return 0;
	return v4.s_addr;
}

static void
ipv6_to_bytes(const char *addr, uint8_t out[16])
{
	struct in6_addr v6;
	if (inet_pton(AF_INET6, addr, &v6) != 1)
		memset(out, 0, 16);
	else
		memcpy(out, &v6, 16);
}

static const struct rte_flow_item *
find_item(const struct rte_flow_parse_result *res, enum rte_flow_item_type type)
{
	for (uint32_t i = 0; i < res->pattern_count; ++i)
		if (res->pattern[i].type == type)
			return &res->pattern[i];
	return NULL;
}

static const struct rte_flow_action *
find_action(const struct rte_flow_parse_result *res, enum rte_flow_action_type type)
{
	for (uint32_t i = 0; i < res->actions_count; ++i)
		if (res->actions[i].type == type)
			return &res->actions[i];
	return NULL;
}

static int
verify_rule_case(int idx, const struct rte_flow_parse_result *res)
{
	const struct rte_flow_item *item;
	const struct rte_flow_action *action;
	const struct rte_flow_item_ipv4 *ipv4;
	const struct rte_flow_item_ipv6 *ipv6;
	const struct rte_flow_action_mark *mark;
	const struct rte_flow_action_queue *queue;
	const struct rte_flow_action_jump *jump;
	uint8_t expected_ipv6[16];

	if (res->port_id != 0)
		return -1;

	switch (idx) {
	case 0:
		if (!res->attr.ingress || res->pattern_count != 2 ||
		    res->actions_count != 1)
			return -1;
		if (res->pattern[0].type != RTE_FLOW_ITEM_TYPE_ETH ||
		    res->pattern[1].type != RTE_FLOW_ITEM_TYPE_IPV4)
			return -1;
		if (res->actions[0].type != RTE_FLOW_ACTION_TYPE_DROP)
			return -1;
		break;
	case 1:
		if (!res->attr.ingress || res->pattern_count != 2 ||
		    res->actions_count != 1)
			return -1;
		item = find_item(res, RTE_FLOW_ITEM_TYPE_IPV4);
		if (!item)
			return -1;
		ipv4 = (const struct rte_flow_item_ipv4 *)item->spec;
		if (!ipv4)
			return -1;
		if (ipv4->hdr.dst_addr != ipv4_to_be32("159.58.1.0") ||
		    ipv4->hdr.src_addr != ipv4_to_be32("195.168.1.0"))
			return -1;
		action = find_action(res, RTE_FLOW_ACTION_TYPE_MARK);
		if (!action)
			return -1;
		mark = (const struct rte_flow_action_mark *)action->conf;
		if (!mark || mark->id != 42)
			return -1;
		break;
	case 2:
		if (!res->attr.ingress || res->actions_count != 2)
			return -1;
		action = find_action(res, RTE_FLOW_ACTION_TYPE_QUEUE);
		if (!action)
			return -1;
		queue = (const struct rte_flow_action_queue *)action->conf;
		if (!queue || queue->index != 1)
			return -1;
		if (res->actions[0].type != RTE_FLOW_ACTION_TYPE_QUEUE &&
		    res->actions[1].type != RTE_FLOW_ACTION_TYPE_QUEUE)
			return -1;
		if (!find_action(res, RTE_FLOW_ACTION_TYPE_FLAG))
			return -1;
		break;
	case 3:
		if (!res->attr.ingress || res->pattern_count != 2)
			return -1;
		item = find_item(res, RTE_FLOW_ITEM_TYPE_IPV6);
		if (!item)
			return -1;
		ipv6 = (const struct rte_flow_item_ipv6 *)item->spec;
		if (!ipv6)
			return -1;
		ipv6_to_bytes("ffee::1", expected_ipv6);
		if (memcmp(ipv6->hdr.src_addr.a, expected_ipv6, sizeof(expected_ipv6)) != 0)
			return -1;
		ipv6 = (const struct rte_flow_item_ipv6 *)item->mask;
		if (!ipv6)
			return -1;
		ipv6_to_bytes("ffff::", expected_ipv6);
		if (memcmp(ipv6->hdr.src_addr.a, expected_ipv6, sizeof(expected_ipv6)) != 0)
			return -1;
		break;
	case 4:
		if (!res->attr.ingress || res->attr.priority != 1)
			return -1;
		if (!find_action(res, RTE_FLOW_ACTION_TYPE_DROP))
			return -1;
		break;
	case 5:
		if (!res->attr.ingress || res->attr.group != 1)
			return -1;
		action = find_action(res, RTE_FLOW_ACTION_TYPE_JUMP);
		if (!action)
			return -1;
		jump = (const struct rte_flow_action_jump *)action->conf;
		if (!jump || jump->group != 2)
			return -1;
		break;
	case 6:
		if (!res->attr.ingress || res->pattern_count != 1)
			return -1;
		if (res->pattern[0].type != RTE_FLOW_ITEM_TYPE_ETH)
			return -1;
		break;
	case 7:
		if (!res->attr.ingress || res->pattern_count != 1)
			return -1;
		if (res->pattern[0].type != RTE_FLOW_ITEM_TYPE_IPV4)
			return -1;
		break;
	case 8:
		if (!res->attr.ingress || res->actions_count != 1)
			return -1;
		if (res->actions[0].type != RTE_FLOW_ACTION_TYPE_FLAG)
			return -1;
		break;
	case 9:
		if (!res->attr.ingress || res->actions_count != 2)
			return -1;
		if (res->actions[0].type != RTE_FLOW_ACTION_TYPE_FLAG ||
		    res->actions[1].type != RTE_FLOW_ACTION_TYPE_QUEUE)
			return -1;
		queue = (const struct rte_flow_action_queue *)res->actions[1].conf;
		if (!queue || queue->index != 1)
			return -1;
		break;
	default:
		return -1;
	}
	return 0;
}

int
main(int argc, char **argv)
{
	struct rte_flow_parser *parser;
	struct rte_flow_error error;
	static const char *rules[] = {
		"flow create 0 ingress pattern eth / ipv4 / end actions drop / end",
		"flow create 0 ingress pattern eth / ipv4 dst is 159.58.1.0 src is 195.168.1.0 / end actions mark id 42 / end",
		"flow create 0 ingress pattern eth / ipv4 dst is 159.58.1.0 src is 195.168.1.0 / end actions queue index 1 / flag / end",
		"flow create 0 ingress pattern eth / ipv6 src spec ffee::1 src mask ffff:: / end actions drop / end",
		"flow create 0 priority 1 ingress pattern eth / ipv4 dst is 159.58.1.0 src is 195.168.1.0 / end actions drop / end",
		"flow create 0 group 1 ingress pattern eth / ipv4 dst is 159.58.1.0 src is 195.168.1.0 / end actions jump group 2 / end",
		"flow create 0 ingress pattern eth / end actions drop / end",
		"flow create 0 ingress pattern ipv4 src is 195.168.0.1 / end actions drop / end",
		"flow create 0 ingress pattern eth / ipv4 dst is 159.58.1.0 src is 195.168.1.0 / end actions flag / end",
		"flow create 0 ingress pattern eth / ipv4 dst is 159.58.1.0 src is 195.168.1.0 / end actions flag / queue index 1 / end",
	};

	struct rte_flow_parse_result result;
	const struct rte_flow_action_mark *mark;
	const struct rte_flow_action_queue *queue;
	int ret;

	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		fprintf(stderr, "failed to init EAL\n");
		return EXIT_FAILURE;
	}

	parser = rte_flow_parser_create(NULL, &error);
	if (!parser) {
		fprintf(stderr, "parser create failed: %s\n",
			error.message ? error.message : "unknown error");
		return EXIT_FAILURE;
	}

	for (uint32_t i = 0; i < ARRAY_SIZE(rules); ++i) {
		memset(&result, 0, sizeof(result));
		if (rte_flow_parser_rule(parser, rules[i], &result, &error)) {
			fprintf(stderr, "rule %u failed to parse: %s\n", i,
				error.message ? error.message : "unknown error");
			rte_flow_parse_result_free(parser, &result);
			rte_flow_parser_destroy(parser);
			return EXIT_FAILURE;
		}
		if (verify_rule_case(i, &result)) {
			fprintf(stderr, "rule %u validation failed\n", i);
			rte_flow_parse_result_free(parser, &result);
			rte_flow_parser_destroy(parser);
			return EXIT_FAILURE;
		}
		rte_flow_parse_result_free(parser, &result);
	}

	/* Pattern only verification */
	struct rte_flow_item *pattern = NULL;
	uint32_t pattern_count = 0;
	if (rte_flow_parser_pattern(parser,
			"pattern eth / ipv4 dst is 159.58.1.0 / end",
			&pattern, &pattern_count, &error)) {
		fprintf(stderr, "pattern parse failed: %s\n",
			error.message ? error.message : "unknown error");
		rte_flow_parser_destroy(parser);
		return EXIT_FAILURE;
	}
	if (pattern_count != 2 || pattern[0].type != RTE_FLOW_ITEM_TYPE_ETH ||
	    pattern[1].type != RTE_FLOW_ITEM_TYPE_IPV4) {
		fprintf(stderr, "pattern validation failed\n");
		rte_flow_parser_pattern_free(parser, pattern);
		rte_flow_parser_destroy(parser);
		return EXIT_FAILURE;
	}
	rte_flow_parser_pattern_free(parser, pattern);

	/* Actions only verification */
	struct rte_flow_action *actions = NULL;
	uint32_t actions_count = 0;
	if (rte_flow_parser_actions(parser,
			"actions mark id 7 / queue index 4 / end",
			&actions, &actions_count, &error)) {
		fprintf(stderr, "actions parse failed: %s\n",
			error.message ? error.message : "unknown error");
		rte_flow_parser_destroy(parser);
		return EXIT_FAILURE;
	}
	if (actions_count != 2 || actions[0].type != RTE_FLOW_ACTION_TYPE_MARK ||
	    actions[1].type != RTE_FLOW_ACTION_TYPE_QUEUE) {
		fprintf(stderr, "actions validation failed\n");
		rte_flow_parser_actions_free(parser, actions);
		rte_flow_parser_destroy(parser);
		return EXIT_FAILURE;
	}
	mark = (const struct rte_flow_action_mark *)actions[0].conf;
	queue = (const struct rte_flow_action_queue *)actions[1].conf;
	if (!mark || mark->id != 7 || !queue || queue->index != 4) {
		fprintf(stderr, "actions detail validation failed\n");
		rte_flow_parser_actions_free(parser, actions);
		rte_flow_parser_destroy(parser);
		return EXIT_FAILURE;
	}
	rte_flow_parser_actions_free(parser, actions);

	rte_flow_parser_destroy(parser);
	rte_eal_cleanup();

	printf("flow parser API self-test passed\n");
	return EXIT_SUCCESS;
}

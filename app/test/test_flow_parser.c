/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>

#include <rte_byteorder.h>
#include <rte_flow.h>
#include <rte_flow_parser.h>

#include "test.h"

static int
flow_parser_setup(void)
{
	TEST_ASSERT_SUCCESS(rte_flow_parser_init(NULL),
		"rte_flow_parser_init failed");
	return 0;
}

static int
flow_parser_case_setup(void)
{
	rte_flow_parser_reset_defaults();
	return 0;
}

static void
flow_parser_teardown(void)
{
	rte_flow_parser_reset_defaults();
}

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

	/* Test flow create command parsing */
	ret = rte_flow_parser_parse(create_cmd, out, sizeof(outbuf));
	TEST_ASSERT_SUCCESS(ret, "flow create parse failed: %s",
		strerror(-ret));
	TEST_ASSERT_EQUAL(out->command, RTE_FLOW_PARSER_CMD_CREATE,
		"expected CREATE command, got %d", out->command);
	TEST_ASSERT_EQUAL(out->port, 0, "expected port 0, got %u", out->port);
	/* pattern: eth / end = 2 items */
	TEST_ASSERT_EQUAL(out->args.vc.pattern_n, 2,
		"expected 2 pattern items, got %u", out->args.vc.pattern_n);
	TEST_ASSERT_EQUAL(out->args.vc.pattern[0].type, RTE_FLOW_ITEM_TYPE_ETH,
		"expected ETH pattern, got %d", out->args.vc.pattern[0].type);
	TEST_ASSERT_EQUAL(out->args.vc.pattern[1].type, RTE_FLOW_ITEM_TYPE_END,
		"expected END pattern, got %d", out->args.vc.pattern[1].type);
	/* actions: drop / end = 2 items */
	TEST_ASSERT_EQUAL(out->args.vc.actions_n, 2,
		"expected 2 action items, got %u", out->args.vc.actions_n);
	TEST_ASSERT_EQUAL(out->args.vc.actions[0].type,
		RTE_FLOW_ACTION_TYPE_DROP,
		"expected DROP action, got %d", out->args.vc.actions[0].type);
	TEST_ASSERT_EQUAL(out->args.vc.actions[1].type,
		RTE_FLOW_ACTION_TYPE_END,
		"expected END action, got %d", out->args.vc.actions[1].type);
	/* ingress attribute */
	TEST_ASSERT(out->args.vc.attr.ingress == 1 &&
		out->args.vc.attr.egress == 0,
		"expected ingress=1 egress=0");

	/* Test flow list command parsing */
	ret = rte_flow_parser_parse(list_cmd, out, sizeof(outbuf));
	TEST_ASSERT_SUCCESS(ret, "flow list parse failed: %s", strerror(-ret));
	TEST_ASSERT_EQUAL(out->command, RTE_FLOW_PARSER_CMD_LIST,
		"expected LIST command, got %d", out->command);
	TEST_ASSERT_EQUAL(out->port, 0, "expected port 0, got %u", out->port);

	return TEST_SUCCESS;
}

static int
test_flow_parser_lightweight_helpers(void)
{
	const struct rte_flow_item *pattern = NULL;
	const struct rte_flow_action *actions = NULL;
	const struct rte_flow_action_queue *queue_conf;
	const struct rte_flow_action_mark *mark_conf;
	struct rte_flow_attr attr;
	uint32_t pattern_n = 0;
	uint32_t actions_n = 0;
	int ret;

	/* Test attribute parsing */
	memset(&attr, 0, sizeof(attr));
	ret = rte_flow_parser_parse_attr_str("ingress group 1 priority 5", &attr);
	TEST_ASSERT_SUCCESS(ret, "attr parse failed: %s", strerror(-ret));
	TEST_ASSERT_EQUAL(attr.group, 1, "attr group mismatch: %u", attr.group);
	TEST_ASSERT_EQUAL(attr.priority, 5,
		"attr priority mismatch: %u", attr.priority);
	TEST_ASSERT(attr.ingress == 1 && attr.egress == 0,
		"attr flags mismatch ingress=%u egress=%u",
		attr.ingress, attr.egress);

	/* Test pattern parsing: eth / ipv4 / end = 3 items */
	ret = rte_flow_parser_parse_pattern_str("eth / ipv4 / end",
						&pattern, &pattern_n);
	TEST_ASSERT_SUCCESS(ret, "pattern parse failed: %s", strerror(-ret));
	TEST_ASSERT_EQUAL(pattern_n, 3, "expected 3 pattern items, got %u",
		pattern_n);
	TEST_ASSERT_EQUAL(pattern[0].type, RTE_FLOW_ITEM_TYPE_ETH,
		"pattern[0] expected ETH, got %d", pattern[0].type);
	TEST_ASSERT_EQUAL(pattern[1].type, RTE_FLOW_ITEM_TYPE_IPV4,
		"pattern[1] expected IPV4, got %d", pattern[1].type);
	TEST_ASSERT_EQUAL(pattern[2].type, RTE_FLOW_ITEM_TYPE_END,
		"pattern[2] expected END, got %d", pattern[2].type);

	/* Test actions parsing with config values: queue index 3 / end = 2 items */
	ret = rte_flow_parser_parse_actions_str("queue index 3 / end",
						&actions, &actions_n);
	TEST_ASSERT_SUCCESS(ret, "actions parse failed: %s", strerror(-ret));
	TEST_ASSERT_EQUAL(actions_n, 2, "expected 2 action items, got %u",
		actions_n);
	TEST_ASSERT_EQUAL(actions[0].type, RTE_FLOW_ACTION_TYPE_QUEUE,
		"actions[0] expected QUEUE, got %d", actions[0].type);
	queue_conf = actions[0].conf;
	TEST_ASSERT_NOT_NULL(queue_conf, "queue action configuration missing");
	TEST_ASSERT_EQUAL(queue_conf->index, 3,
		"queue index expected 3, got %u", queue_conf->index);
	TEST_ASSERT_EQUAL(actions[1].type, RTE_FLOW_ACTION_TYPE_END,
		"actions[1] expected END, got %d", actions[1].type);

	/* Test multiple actions: mark id 42 / drop / end = 3 items */
	ret = rte_flow_parser_parse_actions_str("mark id 42 / drop / end",
						&actions, &actions_n);
	TEST_ASSERT_SUCCESS(ret, "multi-action parse failed: %s",
		strerror(-ret));
	TEST_ASSERT_EQUAL(actions_n, 3, "expected 3 action items, got %u",
		actions_n);
	TEST_ASSERT_EQUAL(actions[0].type, RTE_FLOW_ACTION_TYPE_MARK,
		"actions[0] expected MARK, got %d", actions[0].type);
	mark_conf = actions[0].conf;
	TEST_ASSERT_NOT_NULL(mark_conf, "mark action configuration missing");
	TEST_ASSERT_EQUAL(mark_conf->id, 42,
		"mark id expected 42, got %u", mark_conf->id);
	TEST_ASSERT_EQUAL(actions[1].type, RTE_FLOW_ACTION_TYPE_DROP,
		"actions[1] expected DROP, got %d", actions[1].type);
	TEST_ASSERT_EQUAL(actions[2].type, RTE_FLOW_ACTION_TYPE_END,
		"actions[2] expected END, got %d", actions[2].type);

	/* Test complex pattern: eth / ipv4 / tcp / end = 4 items */
	ret = rte_flow_parser_parse_pattern_str("eth / ipv4 / tcp / end",
						&pattern, &pattern_n);
	TEST_ASSERT_SUCCESS(ret, "complex pattern parse failed: %s",
		strerror(-ret));
	TEST_ASSERT_EQUAL(pattern_n, 4, "expected 4 pattern items, got %u",
		pattern_n);
	TEST_ASSERT(pattern[0].type == RTE_FLOW_ITEM_TYPE_ETH &&
		pattern[1].type == RTE_FLOW_ITEM_TYPE_IPV4 &&
		pattern[2].type == RTE_FLOW_ITEM_TYPE_TCP &&
		pattern[3].type == RTE_FLOW_ITEM_TYPE_END,
		"complex pattern type mismatch");

	return TEST_SUCCESS;
}

static int
test_flow_parser_invalid_args(void)
{
	const struct rte_flow_item *pattern = NULL;
	const struct rte_flow_action *actions = NULL;
	uint8_t outbuf[sizeof(struct rte_flow_parser_output)];
	struct rte_flow_attr attr;
	uint32_t count = 0;
	int ret;

	ret = rte_flow_parser_parse(NULL, (void *)outbuf, sizeof(outbuf));
	TEST_ASSERT_EQUAL(ret, -EINVAL, "NULL cmd should return -EINVAL");

	ret = rte_flow_parser_parse("flow list 0", NULL, sizeof(outbuf));
	TEST_ASSERT_EQUAL(ret, -EINVAL, "NULL output should return -EINVAL");

	ret = rte_flow_parser_parse("flow list 0", (void *)outbuf,
		sizeof(struct rte_flow_parser_output) - 1);
	TEST_ASSERT_EQUAL(ret, -ENOBUFS, "short output buffer not rejected");

	ret = rte_flow_parser_parse_attr_str(NULL, &attr);
	TEST_ASSERT_EQUAL(ret, -EINVAL, "NULL attr string should fail");

	ret = rte_flow_parser_parse_pattern_str(NULL, &pattern, &count);
	TEST_ASSERT_EQUAL(ret, -EINVAL, "NULL pattern string should fail");

	ret = rte_flow_parser_parse_actions_str(NULL, &actions, &count);
	TEST_ASSERT_EQUAL(ret, -EINVAL, "NULL actions string should fail");

	ret = rte_flow_parser_parse_pattern_str("eth / end", NULL, &count);
	TEST_ASSERT_EQUAL(ret, -EINVAL, "NULL pattern out should fail");

	ret = rte_flow_parser_parse_actions_str("drop / end", &actions, NULL);
	TEST_ASSERT_EQUAL(ret, -EINVAL, "NULL actions count should fail");

	return TEST_SUCCESS;
}

static int
test_flow_parser_invalid_commands(void)
{
	static const char *invalid_cmd = "flow invalid 0";
	static const char *incomplete_cmd =
		"flow create 0 ingress pattern eth actions drop / end";
	static const char *valid_cmd =
		"flow destroy 0 rule 7";
	uint8_t outbuf[4096];
	struct rte_flow_parser_output *out = (void *)outbuf;
	int ret;

	ret = rte_flow_parser_parse(invalid_cmd, out, sizeof(outbuf));
	TEST_ASSERT(ret < 0, "unexpected status for invalid cmd: %d", ret);

	ret = rte_flow_parser_parse(incomplete_cmd, out, sizeof(outbuf));
	TEST_ASSERT(ret < 0, "expected failure for incomplete cmd: %d", ret);

	ret = rte_flow_parser_parse(valid_cmd, out, sizeof(outbuf));
	TEST_ASSERT_SUCCESS(ret, "valid cmd failed after errors: %s",
		strerror(-ret));
	TEST_ASSERT_EQUAL(out->command, RTE_FLOW_PARSER_CMD_DESTROY,
		"expected DESTROY command, got %d", out->command);
	TEST_ASSERT_EQUAL(out->args.destroy.rule_n, 1,
		"expected 1 destroy rule, got %" PRIu64,
		out->args.destroy.rule_n);
	TEST_ASSERT_NOT_NULL(out->args.destroy.rule,
		"destroy rule array missing");
	TEST_ASSERT_EQUAL(out->args.destroy.rule[0], 7,
		"expected rule id 7, got %" PRIu64, out->args.destroy.rule[0]);

	return TEST_SUCCESS;
}

static int
test_flow_parser_indirect_action(void)
{
	static const char *flow_indirect_sample =
		"flow indirect_action 0 create transfer list actions sample ratio 1 index 1 / jump group 2 / end";
	uint8_t outbuf[8192];
	struct rte_flow_parser_output *out = (void *)outbuf;
	const struct rte_flow_action *actions;
	const struct rte_flow_action_sample *sample_conf;
	const struct rte_flow_action_ethdev *repr;
	struct rte_flow_action sample_actions[ACTION_SAMPLE_ACTIONS_NUM];
	uint32_t actions_n;
	int ret;

	ret = rte_flow_parser_parse_actions_str(
		"port_representor port_id 0xffff / end",
		&actions, &actions_n);
	TEST_ASSERT_SUCCESS(ret, "parse sample actions failed: %s",
		strerror(-ret));
	TEST_ASSERT(actions_n <= RTE_DIM(sample_actions),
		"sample actions too long");
	memcpy(sample_actions, actions,
		sizeof(struct rte_flow_action) * actions_n);
	memset(out, 0, sizeof(*out));
	out->command = RTE_FLOW_PARSER_CMD_SET_SAMPLE_ACTIONS;
	out->port = 1;
	out->args.vc.actions = sample_actions;
	out->args.vc.actions_n = actions_n;
	rte_flow_parser_cmd_set_raw_dispatch(out);

	ret = rte_flow_parser_parse(flow_indirect_sample, out, sizeof(outbuf));
	TEST_ASSERT_SUCCESS(ret, "indirect sample parse failed: %s",
		strerror(-ret));
	TEST_ASSERT(out->command == RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_LIST_CREATE ||
		out->command == RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_CREATE ||
		out->command == RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_LIST_CREATE ||
		out->command == RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_CREATE,
		"expected indirect action create command, got %d", out->command);
	TEST_ASSERT(out->args.vc.actions_n >= 3,
		"expected sample + jump + end actions for indirect action");
	TEST_ASSERT_EQUAL(out->args.vc.actions[0].type,
		RTE_FLOW_ACTION_TYPE_SAMPLE, "indirect actions[0] not SAMPLE");
	sample_conf = out->args.vc.actions[0].conf;
	TEST_ASSERT_NOT_NULL(sample_conf, "indirect sample conf missing");
	TEST_ASSERT_NOT_NULL(sample_conf->actions,
		"indirect sample actions missing");
	TEST_ASSERT_EQUAL(sample_conf->actions[0].type,
		RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR,
		"indirect sample action[0] type mismatch: %d",
		sample_conf->actions[0].type);
	repr = sample_conf->actions[0].conf;
	TEST_ASSERT_NOT_NULL(repr, "indirect sample port conf missing");
	TEST_ASSERT_EQUAL(repr->port_id, 0xffff,
		"indirect sample port representor id mismatch");
	TEST_ASSERT_EQUAL(sample_conf->actions[1].type,
		RTE_FLOW_ACTION_TYPE_END, "indirect sample actions should end");

	return TEST_SUCCESS;
}

static int
test_flow_parser_meter(void)
{
	static const char *set_policy1 =
		"add port meter policy 0 1 "
		"g_actions queue index 0 / end y_actions end r_actions drop / end";
	static const char *create_meter_m =
		"create port meter 0 100 1 1 yes 0xffff 1 0";
	static const char *set_policy2 =
		"add port meter policy 0 2 "
		"g_actions meter mtr_id 100 / end y_actions end r_actions drop / end";
	static const char *create_meter_n =
		"create port meter 0 101 2 2 yes 0xffff 1 0";
	static const char *flow_meter =
		"flow create 0 ingress group 1 pattern eth / end "
		"actions meter mtr_id 101 / end";
	uint8_t outbuf[8192];
	struct rte_flow_parser_output *out = (void *)outbuf;
	int ret;

	/* Meter programming and use. */
	ret = rte_flow_parser_parse(set_policy1, out, sizeof(outbuf));
	if (ret < 0)
		goto meter_flow;
	TEST_ASSERT_SUCCESS(ret, "set meter policy 1 parse failed: %s",
		strerror(-ret));
	ret = rte_flow_parser_parse(create_meter_m, out, sizeof(outbuf));
	if (ret < 0)
		goto meter_flow;
	TEST_ASSERT_SUCCESS(ret, "create meter M parse failed: %s",
		strerror(-ret));
	ret = rte_flow_parser_parse(set_policy2, out, sizeof(outbuf));
	if (ret < 0)
		goto meter_flow;
	TEST_ASSERT_SUCCESS(ret, "set meter policy 2 parse failed: %s",
		strerror(-ret));
	ret = rte_flow_parser_parse(create_meter_n, out, sizeof(outbuf));
	if (ret < 0)
		goto meter_flow;
	TEST_ASSERT_SUCCESS(ret, "create meter N parse failed: %s",
		strerror(-ret));
meter_flow:
	ret = rte_flow_parser_parse(flow_meter, out, sizeof(outbuf));
	TEST_ASSERT_SUCCESS(ret, "flow meter parse failed: %s", strerror(-ret));
	TEST_ASSERT(out->args.vc.actions_n >= 2,
		"expected meter action in flow");
	TEST_ASSERT_EQUAL(out->args.vc.actions[0].type,
		RTE_FLOW_ACTION_TYPE_METER, "actions[0] not METER");

	return TEST_SUCCESS;
}

static struct unit_test_suite flow_parser_tests = {
	.suite_name = "flow parser autotest",
	.setup = flow_parser_setup,
	.teardown = flow_parser_teardown,
	.unit_test_cases = {
		TEST_CASE_ST(flow_parser_case_setup, NULL,
			test_flow_parser_command_mapping),
		TEST_CASE_ST(flow_parser_case_setup, NULL,
			test_flow_parser_lightweight_helpers),
		TEST_CASE_ST(flow_parser_case_setup, NULL,
			test_flow_parser_invalid_args),
		TEST_CASE_ST(flow_parser_case_setup, NULL,
			test_flow_parser_invalid_commands),
		TEST_CASE_ST(flow_parser_case_setup, NULL,
			test_flow_parser_indirect_action),
		TEST_CASE_ST(flow_parser_case_setup, NULL,
			test_flow_parser_meter),
		TEST_CASES_END()
	}
};

static int
test_flow_parser(void)
{
	return unit_test_suite_runner(&flow_parser_tests);
}

REGISTER_FAST_TEST(flow_parser_autotest, true, true, test_flow_parser);

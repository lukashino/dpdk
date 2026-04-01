/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 Open vSwitch community
 */

#include <string.h>
#include <arpa/inet.h>

#include <rte_flow.h>
#include <rte_flow_pattern_parser.h>

#include "test.h"

static struct rte_flow_pattern_parser *parser;

static int
test_setup(void)
{
	parser = rte_flow_pattern_parser_create();
	if (!parser) {
		printf("Failed to create parser\n");
		return -1;
	}
	return 0;
}

static void
test_teardown(void)
{
	rte_flow_pattern_parser_destroy(parser);
	parser = NULL;
}

/* Count items in a pattern (excluding END). */
static int
count_items(const struct rte_flow_item *pattern)
{
	int n = 0;

	while (pattern[n].type != RTE_FLOW_ITEM_TYPE_END)
		n++;
	return n;
}

/* --- Positive tests --- */

static int
test_bare_eth(void)
{
	struct rte_flow_item *pattern = NULL;
	struct rte_flow_error error;
	int ret;

	ret = rte_flow_pattern_parse(parser, "eth / end", &pattern, &error);
	TEST_ASSERT_EQUAL(ret, 0, "parse failed: %s", error.message);
	TEST_ASSERT_NOT_NULL(pattern, "pattern is NULL");
	TEST_ASSERT_EQUAL(count_items(pattern), 1, "expected 1 item");
	TEST_ASSERT_EQUAL(pattern[0].type, RTE_FLOW_ITEM_TYPE_ETH,
			  "expected ETH");
	TEST_ASSERT_EQUAL(pattern[1].type, RTE_FLOW_ITEM_TYPE_END,
			  "expected END");
	rte_flow_pattern_free(pattern);
	return TEST_SUCCESS;
}

static int
test_ipv4_dst(void)
{
	struct rte_flow_item *pattern = NULL;
	struct rte_flow_error error;
	const struct rte_flow_item_ipv4 *spec;
	struct in_addr expected;
	int ret;

	ret = rte_flow_pattern_parse(parser,
		"eth / ipv4 dst is 192.168.1.1 / end", &pattern, &error);
	TEST_ASSERT_EQUAL(ret, 0, "parse failed: %s", error.message);
	TEST_ASSERT_EQUAL(count_items(pattern), 2, "expected 2 items");
	TEST_ASSERT_EQUAL(pattern[0].type, RTE_FLOW_ITEM_TYPE_ETH, "");
	TEST_ASSERT_EQUAL(pattern[1].type, RTE_FLOW_ITEM_TYPE_IPV4, "");
	TEST_ASSERT_NOT_NULL(pattern[1].spec, "spec should be set");
	TEST_ASSERT_NOT_NULL(pattern[1].mask, "mask should be set (is mode)");

	spec = pattern[1].spec;
	inet_pton(AF_INET, "192.168.1.1", &expected);
	TEST_ASSERT(memcmp(&spec->hdr.dst_addr, &expected, 4) == 0,
		    "dst addr mismatch");

	/* Mask should be all-ff for dst field. */
	const struct rte_flow_item_ipv4 *mask = pattern[1].mask;
	TEST_ASSERT_EQUAL(mask->hdr.dst_addr, 0xffffffff,
			  "mask should be all-ff");

	rte_flow_pattern_free(pattern);
	return TEST_SUCCESS;
}

static int
test_tcp_port(void)
{
	struct rte_flow_item *pattern = NULL;
	struct rte_flow_error error;
	const struct rte_flow_item_tcp *spec;
	int ret;

	ret = rte_flow_pattern_parse(parser,
		"eth / ipv4 / tcp dst is 80 / end", &pattern, &error);
	TEST_ASSERT_EQUAL(ret, 0, "parse failed: %s", error.message);
	TEST_ASSERT_EQUAL(count_items(pattern), 3, "expected 3 items");
	TEST_ASSERT_EQUAL(pattern[2].type, RTE_FLOW_ITEM_TYPE_TCP, "");
	TEST_ASSERT_NOT_NULL(pattern[2].spec, "tcp spec should be set");

	spec = pattern[2].spec;
	TEST_ASSERT_EQUAL(rte_be_to_cpu_16(spec->hdr.dst_port), 80,
			  "dst port should be 80");

	rte_flow_pattern_free(pattern);
	return TEST_SUCCESS;
}

static int
test_spec_mask(void)
{
	struct rte_flow_item *pattern = NULL;
	struct rte_flow_error error;
	const struct rte_flow_item_ipv4 *spec, *mask;
	struct in_addr exp_spec, exp_mask;
	int ret;

	ret = rte_flow_pattern_parse(parser,
		"eth / ipv4 src spec 10.0.0.0 src mask 255.0.0.0 / udp / end",
		&pattern, &error);
	TEST_ASSERT_EQUAL(ret, 0, "parse failed: %s", error.message);
	TEST_ASSERT_EQUAL(count_items(pattern), 3, "expected 3 items");
	TEST_ASSERT_NOT_NULL(pattern[1].spec, "");
	TEST_ASSERT_NOT_NULL(pattern[1].mask, "");

	spec = pattern[1].spec;
	mask = pattern[1].mask;
	inet_pton(AF_INET, "10.0.0.0", &exp_spec);
	inet_pton(AF_INET, "255.0.0.0", &exp_mask);
	TEST_ASSERT(memcmp(&spec->hdr.src_addr, &exp_spec, 4) == 0,
		    "spec mismatch");
	TEST_ASSERT(memcmp(&mask->hdr.src_addr, &exp_mask, 4) == 0,
		    "mask mismatch");

	rte_flow_pattern_free(pattern);
	return TEST_SUCCESS;
}

static int
test_vlan(void)
{
	struct rte_flow_item *pattern = NULL;
	struct rte_flow_error error;
	int ret;

	ret = rte_flow_pattern_parse(parser,
		"eth / vlan vid is 100 / ipv4 / end",
		&pattern, &error);
	TEST_ASSERT_EQUAL(ret, 0, "parse failed: %s", error.message);
	TEST_ASSERT_EQUAL(count_items(pattern), 3, "expected 3 items");
	TEST_ASSERT_EQUAL(pattern[0].type, RTE_FLOW_ITEM_TYPE_ETH, "");
	TEST_ASSERT_EQUAL(pattern[1].type, RTE_FLOW_ITEM_TYPE_VLAN, "");
	TEST_ASSERT_EQUAL(pattern[2].type, RTE_FLOW_ITEM_TYPE_IPV4, "");

	rte_flow_pattern_free(pattern);
	return TEST_SUCCESS;
}

static int
test_void_items(void)
{
	struct rte_flow_item *pattern = NULL;
	struct rte_flow_error error;
	int ret;

	ret = rte_flow_pattern_parse(parser,
		"void / eth / void / end", &pattern, &error);
	TEST_ASSERT_EQUAL(ret, 0, "parse failed: %s", error.message);
	TEST_ASSERT_EQUAL(count_items(pattern), 3, "expected 3 items");
	TEST_ASSERT_EQUAL(pattern[0].type, RTE_FLOW_ITEM_TYPE_VOID, "");
	TEST_ASSERT_EQUAL(pattern[1].type, RTE_FLOW_ITEM_TYPE_ETH, "");
	TEST_ASSERT_EQUAL(pattern[2].type, RTE_FLOW_ITEM_TYPE_VOID, "");

	rte_flow_pattern_free(pattern);
	return TEST_SUCCESS;
}

static int
test_udp_ports(void)
{
	struct rte_flow_item *pattern = NULL;
	struct rte_flow_error error;
	const struct rte_flow_item_udp *spec;
	int ret;

	ret = rte_flow_pattern_parse(parser,
		"eth / ipv4 / udp src is 53 dst is 1234 / end",
		&pattern, &error);
	TEST_ASSERT_EQUAL(ret, 0, "parse failed: %s", error.message);
	spec = pattern[2].spec;
	TEST_ASSERT_NOT_NULL(spec, "udp spec should be set");
	TEST_ASSERT_EQUAL(rte_be_to_cpu_16(spec->hdr.src_port), 53, "");
	TEST_ASSERT_EQUAL(rte_be_to_cpu_16(spec->hdr.dst_port), 1234, "");

	rte_flow_pattern_free(pattern);
	return TEST_SUCCESS;
}

/* --- Negative tests --- */

static int
test_missing_end(void)
{
	struct rte_flow_item *pattern = NULL;
	struct rte_flow_error error;
	int ret;

	ret = rte_flow_pattern_parse(parser, "eth / ipv4",
				     &pattern, &error);
	TEST_ASSERT(ret < 0, "should fail without end");
	TEST_ASSERT_NULL(pattern, "pattern should be NULL on error");
	return TEST_SUCCESS;
}

static int
test_unknown_item(void)
{
	struct rte_flow_item *pattern = NULL;
	struct rte_flow_error error;
	int ret;

	ret = rte_flow_pattern_parse(parser, "eth / foobar / end",
				     &pattern, &error);
	TEST_ASSERT(ret < 0, "should fail with unknown item");
	return TEST_SUCCESS;
}

static int
test_empty_string(void)
{
	struct rte_flow_item *pattern = NULL;
	struct rte_flow_error error;
	int ret;

	ret = rte_flow_pattern_parse(parser, "", &pattern, &error);
	TEST_ASSERT(ret < 0, "should fail with empty string");
	return TEST_SUCCESS;
}

static int
test_null_args(void)
{
	struct rte_flow_item *pattern = NULL;
	int ret;

	ret = rte_flow_pattern_parse(NULL, "eth / end", &pattern, NULL);
	TEST_ASSERT(ret < 0, "should fail with NULL parser");

	ret = rte_flow_pattern_parse(parser, NULL, &pattern, NULL);
	TEST_ASSERT(ret < 0, "should fail with NULL string");

	ret = rte_flow_pattern_parse(parser, "eth / end", NULL, NULL);
	TEST_ASSERT(ret < 0, "should fail with NULL pattern");

	return TEST_SUCCESS;
}

static int
test_invalid_field_value(void)
{
	struct rte_flow_item *pattern = NULL;
	struct rte_flow_error error;
	int ret;

	ret = rte_flow_pattern_parse(parser,
		"eth / ipv4 dst is not_an_ip / end", &pattern, &error);
	TEST_ASSERT(ret < 0, "should fail with invalid IP");
	return TEST_SUCCESS;
}

/* --- Completion tests --- */

static int
test_complete_empty(void)
{
	const char *completions[128];
	int count;

	count = rte_flow_pattern_complete(parser, "", completions, 128);
	TEST_ASSERT(count > 0, "should have completions");
	/* Should include common items like eth, ipv4, etc. */
	int found_eth = 0, found_end = 0;

	for (int i = 0; i < count; i++) {
		if (strcmp(completions[i], "eth") == 0)
			found_eth = 1;
		if (strcmp(completions[i], "end") == 0)
			found_end = 1;
	}
	TEST_ASSERT(found_eth, "should include 'eth'");
	TEST_ASSERT(found_end, "should include 'end'");
	return TEST_SUCCESS;
}

static int
test_complete_partial(void)
{
	const char *completions[128];
	int count;

	count = rte_flow_pattern_complete(parser, "eth / ip",
					  completions, 128);
	TEST_ASSERT(count > 0, "should have completions");
	/* Should include ipv4 and ipv6. */
	int found_ipv4 = 0, found_ipv6 = 0;

	for (int i = 0; i < count; i++) {
		if (strcmp(completions[i], "ipv4") == 0)
			found_ipv4 = 1;
		if (strcmp(completions[i], "ipv6") == 0)
			found_ipv6 = 1;
	}
	TEST_ASSERT(found_ipv4, "should include 'ipv4'");
	TEST_ASSERT(found_ipv6, "should include 'ipv6'");
	return TEST_SUCCESS;
}

/* --- Memory tests --- */

static int
test_parse_free_loop(void)
{
	struct rte_flow_item *pattern;
	struct rte_flow_error error;
	int i, ret;

	/* Parse and free in a loop to check for leaks (run under valgrind). */
	for (i = 0; i < 100; i++) {
		ret = rte_flow_pattern_parse(parser,
			"eth / ipv4 dst is 10.0.0.1 / tcp dst is 80 / end",
			&pattern, &error);
		TEST_ASSERT_EQUAL(ret, 0, "iteration %d failed", i);
		rte_flow_pattern_free(pattern);
	}
	return TEST_SUCCESS;
}

static int
test_free_null(void)
{
	/* Should not crash. */
	rte_flow_pattern_free(NULL);
	return TEST_SUCCESS;
}

static struct unit_test_suite flow_pattern_parser_suite = {
	.suite_name = "flow_pattern_parser",
	.setup = test_setup,
	.teardown = test_teardown,
	.unit_test_cases = {
		/* Positive tests. */
		TEST_CASE(test_bare_eth),
		TEST_CASE(test_ipv4_dst),
		TEST_CASE(test_tcp_port),
		TEST_CASE(test_spec_mask),
		TEST_CASE(test_vlan),
		TEST_CASE(test_void_items),
		TEST_CASE(test_udp_ports),
		/* Negative tests. */
		TEST_CASE(test_missing_end),
		TEST_CASE(test_unknown_item),
		TEST_CASE(test_empty_string),
		TEST_CASE(test_null_args),
		TEST_CASE(test_invalid_field_value),
		/* Completion tests. */
		TEST_CASE(test_complete_empty),
		TEST_CASE(test_complete_partial),
		/* Memory tests. */
		TEST_CASE(test_parse_free_loop),
		TEST_CASE(test_free_null),
		TEST_CASES_END()
	}
};

static int
test_flow_pattern_parser(void)
{
	return unit_test_suite_runner(&flow_pattern_parser_suite);
}

REGISTER_FAST_TEST(flow_pattern_parser_autotest,
		   NOHUGE_OK, ASAN_OK, test_flow_pattern_parser);

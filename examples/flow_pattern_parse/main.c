/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 Open vSwitch community
 */

/*
 * Example application demonstrating the rte_flow_pattern_parser API.
 *
 * Parses several pattern strings into rte_flow_item arrays,
 * prints the results, and demonstrates the completion API.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include <rte_eal.h>
#include <rte_flow.h>
#include <rte_flow_pattern_parser.h>

static const char *
item_type_name(enum rte_flow_item_type type)
{
	switch (type) {
	case RTE_FLOW_ITEM_TYPE_END: return "END";
	case RTE_FLOW_ITEM_TYPE_VOID: return "VOID";
	case RTE_FLOW_ITEM_TYPE_ETH: return "ETH";
	case RTE_FLOW_ITEM_TYPE_VLAN: return "VLAN";
	case RTE_FLOW_ITEM_TYPE_IPV4: return "IPV4";
	case RTE_FLOW_ITEM_TYPE_IPV6: return "IPV6";
	case RTE_FLOW_ITEM_TYPE_ICMP: return "ICMP";
	case RTE_FLOW_ITEM_TYPE_UDP: return "UDP";
	case RTE_FLOW_ITEM_TYPE_TCP: return "TCP";
	case RTE_FLOW_ITEM_TYPE_SCTP: return "SCTP";
	case RTE_FLOW_ITEM_TYPE_VXLAN: return "VXLAN";
	case RTE_FLOW_ITEM_TYPE_GRE: return "GRE";
	case RTE_FLOW_ITEM_TYPE_GTP: return "GTP";
	case RTE_FLOW_ITEM_TYPE_GENEVE: return "GENEVE";
	case RTE_FLOW_ITEM_TYPE_ANY: return "ANY";
	default: return "UNKNOWN";
	}
}

static void
print_ipv4(const char *label, const void *spec)
{
	const struct rte_flow_item_ipv4 *ipv4 = spec;
	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &ipv4->hdr.src_addr, src, sizeof(src));
	inet_ntop(AF_INET, &ipv4->hdr.dst_addr, dst, sizeof(dst));
	printf("    %s: src=%s dst=%s proto=%u ttl=%u\n",
	       label, src, dst, ipv4->hdr.next_proto_id,
	       ipv4->hdr.time_to_live);
}

static void
print_tcp(const char *label, const void *spec)
{
	const struct rte_flow_item_tcp *tcp = spec;

	printf("    %s: src_port=%u dst_port=%u flags=0x%02x\n",
	       label,
	       rte_be_to_cpu_16(tcp->hdr.src_port),
	       rte_be_to_cpu_16(tcp->hdr.dst_port),
	       tcp->hdr.tcp_flags);
}

static void
print_udp(const char *label, const void *spec)
{
	const struct rte_flow_item_udp *udp = spec;

	printf("    %s: src_port=%u dst_port=%u\n",
	       label,
	       rte_be_to_cpu_16(udp->hdr.src_port),
	       rte_be_to_cpu_16(udp->hdr.dst_port));
}

static void
print_pattern(const struct rte_flow_item *pattern)
{
	const struct rte_flow_item *item;
	int idx = 0;

	for (item = pattern; item->type != RTE_FLOW_ITEM_TYPE_END;
	     item++, idx++) {
		printf("  item[%d]: type=%s (%d)", idx,
		       item_type_name(item->type), item->type);
		if (item->spec)
			printf(" [has spec]");
		if (item->mask)
			printf(" [has mask]");
		if (item->last)
			printf(" [has last]");
		printf("\n");

		/* Print details for common types. */
		if (item->spec) {
			switch (item->type) {
			case RTE_FLOW_ITEM_TYPE_IPV4:
				print_ipv4("spec", item->spec);
				if (item->mask)
					print_ipv4("mask", item->mask);
				break;
			case RTE_FLOW_ITEM_TYPE_TCP:
				print_tcp("spec", item->spec);
				break;
			case RTE_FLOW_ITEM_TYPE_UDP:
				print_udp("spec", item->spec);
				break;
			default:
				break;
			}
		}
	}
	printf("  item[%d]: type=END\n", idx);
}

static void
test_parse(struct rte_flow_pattern_parser *parser, const char *desc,
	   const char *pattern_str)
{
	struct rte_flow_item *pattern = NULL;
	struct rte_flow_error error;
	int ret;

	printf("\n--- %s ---\n", desc);
	printf("Input: \"%s\"\n", pattern_str);

	ret = rte_flow_pattern_parse(parser, pattern_str, &pattern, &error);
	if (ret != 0) {
		printf("FAILED: %s (error %d)\n",
		       error.message ? error.message : "(unknown)", ret);
		return;
	}

	printf("OK: parsed items:\n");
	print_pattern(pattern);
	rte_flow_pattern_free(pattern);
}

static void
test_completions(struct rte_flow_pattern_parser *parser)
{
	const char *completions[64];
	int count, i;

	printf("\n--- Completion test ---\n");

	/* Complete from empty string - should show all item types. */
	count = rte_flow_pattern_complete(parser, "", completions, 64);
	printf("Empty string completions (%d): ", count);
	for (i = 0; i < count && i < 10; i++)
		printf("%s ", completions[i]);
	if (count > 10)
		printf("...");
	printf("\n");

	/* Complete after "eth / " - should show all item types. */
	count = rte_flow_pattern_complete(parser, "eth / ", completions, 64);
	printf("After 'eth / ' (%d): ", count);
	for (i = 0; i < count && i < 10; i++)
		printf("%s ", completions[i]);
	if (count > 10)
		printf("...");
	printf("\n");

	/* Complete partial "eth / ip" - should match ipv4, ipv6. */
	count = rte_flow_pattern_complete(parser, "eth / ip", completions, 64);
	printf("Partial 'eth / ip' (%d): ", count);
	for (i = 0; i < count; i++)
		printf("%s ", completions[i]);
	printf("\n");
}

int
main(int argc, char *argv[])
{
	struct rte_flow_pattern_parser *parser;
	int ret;

	/* Initialize EAL. */
	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		fprintf(stderr, "EAL init failed: %d\n", ret);
		return 1;
	}

	/* Create parser context. */
	parser = rte_flow_pattern_parser_create();
	if (!parser) {
		fprintf(stderr, "Failed to create parser\n");
		rte_eal_cleanup();
		return 1;
	}

	printf("=== rte_flow Pattern Parser Example ===\n");

	/* Test 1: Bare Ethernet match. */
	test_parse(parser, "Bare Ethernet", "eth / end");

	/* Test 2: IPv4 with field specification. */
	test_parse(parser, "IPv4 with dst",
		   "eth / ipv4 dst is 192.168.1.1 / end");

	/* Test 3: L3 + L4 matching. */
	test_parse(parser, "TCP port 80",
		   "eth / ipv4 / tcp dst is 80 / end");

	/* Test 4: spec + mask for subnet matching. */
	test_parse(parser, "IPv4 subnet via spec+mask",
		   "eth / ipv4 src spec 10.0.0.0 src mask 255.0.0.0 / udp / end");

	/* Test 5: VLAN tagged traffic. */
	test_parse(parser, "VLAN tagged",
		   "eth / vlan vid is 100 / ipv4 / end");

	/* Test 6: Error case - missing end. */
	test_parse(parser, "Error: missing end",
		   "eth / ipv4");

	/* Test 7: Error case - unknown item. */
	test_parse(parser, "Error: unknown item",
		   "eth / foobar / end");

	/* Test completions. */
	test_completions(parser);

	/* Cleanup. */
	rte_flow_pattern_parser_destroy(parser);
	rte_eal_cleanup();

	printf("\nDone.\n");
	return 0;
}

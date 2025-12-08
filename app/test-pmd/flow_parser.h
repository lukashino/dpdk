/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _TESTPMD_FLOW_PARSER_H_
#define _TESTPMD_FLOW_PARSER_H_

#include <rte_flow_parser.h>

struct rte_flow_parser_vxlan_encap_conf *testpmd_vxlan_encap_conf(void);
struct rte_flow_parser_nvgre_encap_conf *testpmd_nvgre_encap_conf(void);
struct rte_flow_parser_l2_encap_conf *testpmd_l2_encap_conf(void);
struct rte_flow_parser_l2_decap_conf *testpmd_l2_decap_conf(void);
struct rte_flow_parser_mplsogre_encap_conf *testpmd_mplsogre_encap_conf(void);
struct rte_flow_parser_mplsogre_decap_conf *testpmd_mplsogre_decap_conf(void);
struct rte_flow_parser_mplsoudp_encap_conf *testpmd_mplsoudp_encap_conf(void);
struct rte_flow_parser_mplsoudp_decap_conf *testpmd_mplsoudp_decap_conf(void);

#endif /* _TESTPMD_FLOW_PARSER_H_ */
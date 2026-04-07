..  SPDX-License-Identifier: BSD-3-Clause

Flow Parser Library
===================

Overview
--------

The flow parser library provides **one way** to create ``rte_flow`` C structures
by parsing testpmd-style command strings. This is particularly useful for
applications that need to accept flow rules from user input, configuration
files, or external control planes using the familiar testpmd syntax.

.. note::

   This library is not the only way to create rte_flow structures. Applications
   can also construct ``struct rte_flow_attr``, ``struct rte_flow_item[]``, and
   ``struct rte_flow_action[]`` directly in C code and pass them to the rte_flow
   API (``rte_flow_create()``, ``rte_flow_validate()``, etc.). The parser library
   is an alternative approach for cases where string-based input is preferred.

Public API
----------

The simple API is declared in ``rte_flow_parser.h`` and consists of
three parse helpers plus configuration accessors:

* ``rte_flow_parser_parse_attr_str()`` - Parse flow attributes from a string.
* ``rte_flow_parser_parse_pattern_str()`` - Parse flow pattern from a string.
* ``rte_flow_parser_parse_actions_str()`` - Parse flow actions from a string.

These functions provide lightweight parsing of testpmd-style flow rule
fragments into standard ``rte_flow`` C structures that can be used with
``rte_flow_create()``, ``rte_flow_validate()``, and other rte_flow APIs.
These helpers use internal storage, meaning, that the returned pointers remain
valid until the next parse call on the same thread.

.. note::

   Additional functions for full command parsing and cmdline integration are
   available in ``rte_flow_parser_cmdline.h``. These include
   ``rte_flow_parser_parse()`` for parsing complete flow CLI strings and
   cmdline token callbacks for building interactive command interfaces.

Example Usage
-------------

``examples/flow_parsing/main.c`` demonstrates the lightweight parsing helpers:

* Parse flow attributes with ``rte_flow_parser_parse_attr_str()``.
* Parse match patterns with ``rte_flow_parser_parse_pattern_str()``.
* Parse flow actions with ``rte_flow_parser_parse_actions_str()``.
* Print parsed results showing the structured data.

Build and run the example::

  meson configure -Dexamples=flow_parsing build
  ninja -C build
  ./build/examples/dpdk-flow_parsing

The output shows each parsed flow component, demonstrating that the parser
is decoupled from testpmd and usable in standalone applications without
requiring EAL initialization.

One-Shot Flow Rule Parsing
--------------------------

``rte_flow_parser_parse_flow_rule()`` parses a complete flow rule string
(attributes + pattern + actions) in a single call::

  struct rte_flow_attr attr;
  const struct rte_flow_item *pattern;
  const struct rte_flow_action *actions;
  uint32_t pattern_n, actions_n;

  ret = rte_flow_parser_parse_flow_rule(
      "ingress pattern eth / ipv4 / end actions drop / end",
      &attr, &pattern, &pattern_n, &actions, &actions_n);

This is equivalent to calling the three helpers individually but avoids the
caller having to split the string into attribute/pattern/action fragments.

Full Command Parsing
--------------------

The header ``rte_flow_parser_cmdline.h`` provides the full command parser
used by testpmd and other applications that need to handle all flow CLI
commands (create, destroy, query, template operations, etc.).

``rte_flow_parser_parse()`` parses a complete flow CLI string into a
``struct rte_flow_parser_output`` buffer::

  uint8_t buf[4096];
  struct rte_flow_parser_output *out = (void *)buf;

  ret = rte_flow_parser_parse(
      "flow create 0 ingress pattern eth / ipv4 / end actions drop / end",
      out, sizeof(buf));

  /* out->command == RTE_FLOW_PARSER_CMD_CREATE */
  /* out->port == 0 */
  /* out->args.vc.pattern, out->args.vc.actions populated */

Parser-internal commands (``set raw_encap``, ``set raw_decap``) are dispatched
via the registered callback and the state can be stored using the setter APIs
(``rte_flow_parser_raw_encap_conf_set()``, ``rte_flow_parser_raw_decap_conf_set()``).
Applications dispatch the result by switching on ``out->command``.

Interactive Cmdline Integration
-------------------------------

Applications that want testpmd-like interactive flow parsing with tab
completion use the cmdline integration API. The library provides complete
``cmdline_parse_inst_t`` callbacks that encapsulate the dynamic token
protocol used by the DPDK cmdline library.

Setup requires three steps:

1. Declare ``cmdline_parse_inst_t`` instances using the library callbacks::

     #include <rte_flow_parser_cmdline.h>

     cmdline_parse_inst_t cmd_flow = {
         .f = rte_flow_parser_cmd_flow_cb,
         .tokens = { NULL },  /* dynamic tokens */
     };

     cmdline_parse_inst_t cmd_set_raw = {
         .f = rte_flow_parser_cmd_set_raw_cb,
         .tokens = { NULL },  /* dynamic tokens */
     };

2. Register instances and provide a dispatch callback::

     static void
     my_dispatch(const struct rte_flow_parser_output *out)
     {
         switch (out->command) {
         case RTE_FLOW_PARSER_CMD_CREATE:
             /* call rte_flow_create() ... */
             break;
         case RTE_FLOW_PARSER_CMD_DESTROY:
             /* call rte_flow_destroy() ... */
             break;
         /* ... */
         }
     }

     rte_flow_parser_cmdline_register(&cmd_flow, &cmd_set_raw,
                                      my_dispatch);

3. Add ``cmd_flow`` and ``cmd_set_raw`` to the cmdline context array.

The library handles token population, tab completion, and context-sensitive
help automatically. When a complete command is parsed, the library calls
the registered dispatch function. SET commands are auto-applied internally.

.. note::

   The library writes to ``inst->help_str`` dynamically during interactive
   parsing to provide context-sensitive help. The registered instances must
   remain valid for the lifetime of the cmdline session.

Encapsulation Configuration
---------------------------

Certain flow actions (``vxlan_encap``, ``nvgre_encap``, ``l2_encap``, etc.)
require pre-configured tunnel parameters. Applications configure these via
accessor functions before parsing flow rules that reference them::

  struct rte_flow_parser_vxlan_encap_conf *vxlan =
      rte_flow_parser_vxlan_encap_conf();
  vxlan->select_ipv4 = 1;
  vxlan->vni[0] = 0x12;
  vxlan->vni[1] = 0x34;
  vxlan->vni[2] = 0x56;
  /* Now parsing "actions vxlan_encap / end" uses this config */

Available accessors: ``rte_flow_parser_vxlan_encap_conf()``,
``rte_flow_parser_nvgre_encap_conf()``, ``rte_flow_parser_l2_encap_conf()``,
``rte_flow_parser_l2_decap_conf()``, ``rte_flow_parser_mplsogre_encap_conf()``,
``rte_flow_parser_mplsogre_decap_conf()``,
``rte_flow_parser_mplsoudp_encap_conf()``,
``rte_flow_parser_mplsoudp_decap_conf()``,
``rte_flow_parser_conntrack_context()``.

For raw encap/decap, use ``rte_flow_parser_raw_encap_conf_set()`` or
``rte_flow_parser_raw_decap_conf_set()`` to store configuration, then inspect
the stored data via ``rte_flow_parser_raw_encap_conf()`` or
``rte_flow_parser_raw_decap_conf()``.

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

The parser is built as part of ``librte_ethdev`` and initializes
automatically via ``RTE_INIT`` -- no explicit init call is required.

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

.. note::

   Additional functions for full command parsing and cmdline integration are
   available in ``rte_flow_parser_cmdline.h``. These include
   ``rte_flow_parser_parse()`` for parsing complete flow CLI strings,
   ``rte_flow_parser_apply()`` for applying parser-internal commands, and
   cmdline token callbacks for building interactive command interfaces.

Parsing Helpers
---------------

The public API provides lightweight helpers to parse flow rule fragments:

* ``rte_flow_parser_parse_attr_str(src, attr)`` parses flow attributes
  (e.g., ``"ingress group 1 priority 5"``) into the provided
  ``struct rte_flow_attr``.
* ``rte_flow_parser_parse_pattern_str(src, pattern, pattern_n)`` parses
  a pattern list (e.g., ``"eth / ipv4 src is 192.168.1.1 / tcp / end"``)
  and returns a pointer to the resulting ``struct rte_flow_item`` array
  plus its length.
* ``rte_flow_parser_parse_actions_str(src, actions, actions_n)`` parses
  an actions list (e.g., ``"queue index 5 / count / end"``) and returns
  a pointer to the resulting ``struct rte_flow_action`` array plus its length.

These helpers use internal storage; the returned pointers remain valid until
the next parse call on the same thread.

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

Full Command Parsing (testpmd integration)
------------------------------------------

The header ``rte_flow_parser_cmdline.h`` provides additional functionality
used by testpmd and DPDK test applications:

* ``rte_flow_parser_parse()`` - Parse complete flow CLI strings with auto-apply.
* ``rte_flow_parser_apply()`` - Apply parser-internal SET commands.
* Cmdline integration (``rte_flow_parser_cmdline_register()``, token callbacks).
* Encapsulation configuration accessors (``rte_flow_parser_*_conf()`` functions).
* Parser state reset (``rte_flow_parser_reset_defaults()``).

Applications using the cmdline API dispatch parsed commands themselves, calling
their own port_flow_* functions directly from a switch on the command index.

.. SPDX-License-Identifier: BSD-3-Clause
   Copyright 2026 The DPDK contributors

.. include:: <isonum.txt>

DPDK Release 26.07
==================

New Features
------------

* **Added experimental RSS type helper APIs in ethdev.**

  * Added new APIs to convert between RSS type names and values.
  * Added new API call to obtain the global RSS string table.

* **Added experimental flow parser to ethdev.**

  * Introduced ``rte_flow_parser`` helpers in ethdev to convert the
    testpmd's ``flow`` CLI commands into ``rte_flow`` structures.
    See ``rte_flow_parser.h`` and ``rte_flow_parser_cmdline.h``.


Removed Items
-------------


ABI Changes
-----------


Tested Platforms
----------------



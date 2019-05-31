=================
OPAL Dump Regions
=================

.. code-block:: c

   #define OPAL_REGISTER_DUMP_REGION		101
   #define OPAL_UNREGISTER_DUMP_REGION		102

   int64_t opal_register_dump_region(uint32_t id, uint64_t addr, uint64_t size);
   int64_t opal_unregister_dump_region(uint32_t id);

In the event of crashes, some service processors and firmware support gathering
a limited amount of memory from a limited number of memory regions to save into
a debug dump that can be useful for firmware and operating system developers
in diagnosing problems. Typically, firmware and kernel log buffers are useful to
save in a dump.

.. _OPAL_REGISTER_DUMP_REGION:

OPAL_REGISTER_DUMP_REGION
=========================

.. code-block:: c

   #define OPAL_REGISTER_DUMP_REGION		101

   int64_t opal_register_dump_region(uint32_t id, uint64_t addr, uint64_t size);

This call is used to register regions of memory for a service processor to capture
when the host crashes.

e.g. if an assert is hit in OPAL, a service processor will copy the region of
memory into some kind of crash dump for further analysis.

This is an OPTIONAL feature that may be unsupported, the host OS should use an
:ref:`OPAL_CHECK_TOKEN` call to find out if :ref:`OPAL_REGISTER_DUMP_REGION` is supported.

:ref:`OPAL_REGISTER_DUMP_REGION` accepts 3 parameters:

- region ID
- address
- length

There is a range of region IDs that can be used by the host OS. A host OS should
start from OPAL_DUMP_REGION_HOST_END and work down if it wants to add a not well
defined region to dump. Currently the only well defined region is for the host
OS log buffer (e.g. dmesg on linux). ::

  /*
   * Dump region ID range usable by the OS
   */
   #define OPAL_DUMP_REGION_HOST_START		0x80
   #define OPAL_DUMP_REGION_LOG_BUF		0x80
   #define OPAL_DUMP_REGION_HOST_END		0xFF

:ref:`OPAL_REGISTER_DUMP_REGION` will return :ref:`OPAL_UNSUPPORTED` if the call is present but
the system doesn't support registering regions to be dumped.

In the event of being passed an invalid region ID, :ref:`OPAL_REGISTER_DUMP_REGION` will
return :ref:`OPAL_PARAMETER`.

Systems likely have a limit as to how many regions they can support being dumped. If
this limit is reached, :ref:`OPAL_REGISTER_DUMP_REGION` will return :ref:`OPAL_INTERNAL_ERROR`.

BUGS
----
Some skiboot versions incorrectly returned :ref:`OPAL_SUCCESS` in the case of
:ref:`OPAL_REGISTER_DUMP_REGION` being supported on a platform (so the call was present)
but the call being unsupported for some reason (e.g. on an IBM POWER7 machine).

See also: :ref:`OPAL_UNREGISTER_DUMP_REGION`

.. _OPAL_UNREGISTER_DUMP_REGION:

OPAL_UNREGISTER_DUMP_REGION
===========================

.. code-block:: c

   #define OPAL_UNREGISTER_DUMP_REGION		102

   int64_t opal_unregister_dump_region(uint32_t id);

While :ref:`OPAL_REGISTER_DUMP_REGION` registers a region, :ref:`OPAL_UNREGISTER_DUMP_REGION`
will unregister a region by region ID.

:ref:`OPAL_UNREGISTER_DUMP_REGION` takes one argument: the region ID.

A host OS should check :ref:`OPAL_UNREGISTER_DUMP_REGION` is supported through a call to
:ref:`OPAL_CHECK_TOKEN`.

If :ref:`OPAL_UNREGISTER_DUMP_REGION` is called on a system where the call is present but
unsupported, it will return :ref:`OPAL_UNSUPPORTED`.

BUGS
----
Some skiboot versions incorrectly returned :ref:`OPAL_SUCCESS` in the case of
:ref:`OPAL_UNREGISTER_DUMP_REGION` being supported on a platform (so the call was present)
but the call being unsupported for some reason (e.g. on an IBM POWER7 machine).

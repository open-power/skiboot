.. _OPAL_NPU_SPA_SETUP:

OPAL_NPU_SPA_SETUP
==================

OpenCAPI devices only.

Sets up a Shared Process Area (SPA) with the Shared Process Area
Pointer (SPAP) set to the provided address `addr`, and sets the OTL PE
mask (used for PASID to PE handle conversion) to `PE_mask`.

If `addr` is NULL, the SPA will be disabled. `addr` must be 4K aligned.

Parameters
----------
::

   uint64_t phb_id
   int bdfn
   uint64_t addr
   uint64_t PE_mask

``phb_id``
   OPAL ID of PHB

``bdfn``
   Bus-Device-Function number of OpenCAPI AFU

``addr``
   Address of Shared Process Area, or NULL to disable SPA. Must be 4K aligned.

``PE_mask``
   Process Element mask for PASID to PE handle conversion

Return Values
-------------

OPAL_SUCCESS
   SPAP and PE mask were successfully set

OPAL_PARAMETER
   A provided parameter was invalid

OPAL_BUSY
   SPA is already enabled (or if addr is NULL, SPA is already disabled)

.. _OPAL_NPU_SPA_CLEAR_CACHE:

OPAL_NPU_SPA_CLEAR_CACHE
========================

OpenCAPI devices only.

Invalidates the Process Element with the given `PE_handle` from the NPU's SPA cache.

Parameters
----------
::

   uint64_t phb_id
   uint32_t bdfn
   uint64_t PE_handle

``phb_id``
   OPAL ID of PHB

``bdfn``
   Bus-Device-Function number of OpenCAPI AFU

``PE_handle``
   Handle of Process Element being cleared from SPA cache

Return Values
-------------

OPAL_SUCCESS
   PE was successfully cleared from SPA cache

OPAL_PARAMETER
   A provided parameter was invalid

OPAL_BUSY
   XSLO is currently invalidating a previously requested entry

.. _OPAL_NPU_TL_SET:

OPAL_NPU_TL_SET
===============

OpenCAPI devices only.

Update the NPU OTL configuration with device capabilities.

Parameters
----------
::

   uint64_t phb_id
   uint32_t bdfn
   long capabilities
   uint64_t rate_phys
   int rate_sz

``phb_id``
   OPAL ID of PHB

``bdfn``
   Bus-Device-Function number of OpenCAPI AFU

``capabilities``
   Bitmap of TL templates the device can receive

``rate_phys``
   Physical address of rates buffer

``rate_sz``
   Size of rates buffer (must be equal to 32)

Return Values
-------------

OPAL_SUCCESS
   OTL configuration was successfully updated

OPAL_PARAMETER
   A provided parameter was invalid

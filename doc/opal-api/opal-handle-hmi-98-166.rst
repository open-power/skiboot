Hypervisor Maintenance Interrupt (HMI)
======================================

  Hypervisor Maintenance Interrupt usually reports error related to processor
  recovery/checkstop, NX/NPU checkstop and Timer facility. Hypervisor then
  takes this opportunity to analyze and recover from some of these errors.
  Hypervisor takes assistance from OPAL layer to handle and recover from HMI.
  After handling HMI, OPAL layer sends the summary of error report and status
  of recovery action using HMI event. See ref: `opal-messages.rst` for HMI
  event structure under ```OPAL_MSG_HMI_EVT``` section.

  HMI is thread specific. The reason for HMI is available in a per thread
  Hypervisor Maintenance Exception Register (HMER). A Hypervisor Maintenance
  Exception Enable Register (HMEER) is per core. Bits from the HMER need to
  be enabled by the corresponding bits in the HMEER in order to cause an HMI.

  Several interrupt reasons are routed in parallel to each of the thread
  specific copies. Each thread can only clear bits in its own HMER. OPAL
  handler from each thread clears the respective bit from HMER register
  after handling the error.

List of errors that causes HMI
==============================

  - CPU Errors

   - Processor Core checkstop
   - Processor retry recovery
   - NX/NPU/CAPP checkstop.

  - Timer facility Errors

   - ChipTOD Errors

    - ChipTOD sync check and parity errors
    - ChipTOD configuration register parity errors
    - ChiTOD topology failover

   - Timebase (TB) errors

    - TB parity/residue error
    - TFMR parity and firmware control error
    - DEC/HDEC/PURR/SPURR parity errors

HMI handling
============

   A core/NX/NPU checkstops are reported as malfunction alert (HMER bit 0).
   OPAL handler scans through Fault Isolation Register (FIR) for each
   core/nx/npu to detect the exact reason for checkstop and reports it back
   to the host alongwith the disposition.

   A processor recovery is reported through HMER bits 2, 3 and 11. These are
   just an informational messages and no extra recovery is required.

   Timer facility errors are reported through HMER bit 4. These are all
   recoverable errors. The exact reason for the errors are stored in
   Timer Facility Management Register (TFMR). Some of the Timer facility
   errors affects TB and some of them affects TOD. TOD is a per chip
   Time-Of-Day logic that holds the actual time value of the chip and
   communicates with every TOD in the system to achieve synchronized
   timer value within a system. TB is per core register (64-bit) derives its
   value from ChipTOD at startup and then it gets periodically incremented
   by STEP signal provided by the TOD. In a multi-socket system TODs are
   always configured as master/backup TOD under primary/secondary
   topology configuration respectively.

   TB error generates HMI on all threads of the affected core. TB errors
   except DEC/HDEC/PURR/SPURR parity errors, causes TB to stop running
   making it invalid. As part of TB recovery, OPAL hmi handler synchronizes
   with all threads, clears the TB errors and then re-sync the TB with TOD
   value putting it back in running state.

   TOD errors generates HMI on every core/thread of affected chip. The reason
   for TOD errors are stored in TOD ERROR register (0x40030). As part of the
   recovery OPAL hmi handler clears the TOD error and then requests new TOD
   value from another running chipTOD in the system. Sometimes, if a primary
   chipTOD is in error, it may need a TOD topology switch to recover from
   error. A TOD topology switch basically makes a backup as new active master.

OPAL_HANDLE_HMI and OPAL_HANDLE_HMI2
====================================
::

   #define OPAL_HANDLE_HMI	98
   #define OPAL_HANDLE_HMI2	166

``OPAL_HANDLE_HMI``

``OPAL_HANDLE_HMI2``
  When OS host gets an Hypervisor Maintenance Interrupt (HMI), it must call
  ```OPAL_HANDLE_HMI``` or ```OPAL_HANDLE_HMI2```. The ```OPAL_HANDLE_HMI```
  is an old interface. ```OPAL_HANDLE_HMI2``` is newly introduced opal call
  that returns direct info to Linux. It returns a 64-bit flag mask currently
  set to provide info about which timer facilities were lost, and whether an
  event was generated. This information will help OS to take respective
  actions.

  In case where opal hmi handler is unable to recover from TOD or TB errors,
  it would flag ```OPAL_HMI_FLAGS_TOD_TB_FAIL``` to indicate OS that TB is
  dead. This information then can be used by OS to make sure that the
  functions relying on TB value (e.g. udelay()) are aware of TB not ticking.
  This will avoid OS getting stuck or hang during its way to panic path.

OPAL_HANDLE_HMI
---------------
Syntax: ::

  int64_t opal_handle_hmi(void)

OPAL_HANDLE_HMI2
----------------
Syntax: ::

  int64_t opal_handle_hmi2(__be64 *out_flags)

parameters
^^^^^^^^^^

  ``__be64 *out_flags``

  Returns the 64-bit flag mask that provides info about which timer facilities
  were lost, and whether an event was generated.

::

   /* OPAL_HANDLE_HMI2 out_flags */
   enum {
        OPAL_HMI_FLAGS_TB_RESYNC        = (1ull << 0), /* Timebase has been resynced */
        OPAL_HMI_FLAGS_DEC_LOST         = (1ull << 1), /* DEC lost, needs to be reprogrammed */
        OPAL_HMI_FLAGS_HDEC_LOST        = (1ull << 2), /* HDEC lost, needs to be reprogrammed */
        OPAL_HMI_FLAGS_TOD_TB_FAIL      = (1ull << 3), /* TOD/TB recovery failed. */
        OPAL_HMI_FLAGS_NEW_EVENT        = (1ull << 63), /* An event has been created */
   };

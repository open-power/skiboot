.. _OPAL_SIGNAL_SYSTEM_RESET:

OPAL_SIGNAL_SYSTEM_RESET
========================
::

   int64_t signal_system_reset(int32_t cpu_nr);
 
This OPAL call causes the specified cpu(s) to be reset to the system
reset exception handler (0x100).

The exact contents of system registers (e.g., SRR1 wakeup causes) may
vary depending on implementation and should not be relied upon.

Resetting active threads on the same core as this call is run may
not be supported by some platforms. In that case, OPAL_PARTIAL will be
returned and NONE of the interrupts will be delivered.

Arguments
---------
::

  int32_t cpu_nr
    cpu_nr >= 0        The cpu server number of the target cpu to reset.
    SYS_RESET_ALL (-1) All cpus should be reset.
    SYS_RESET_ALL_OTHERS (-2) All but the current cpu should be reset.

Returns
-------
OPAL_SUCCESS
  The power down was updated successful.

OPAL_PARAMETER
  A parameter was incorrect.

OPAL_HARDWARE
  Hardware indicated failure during reset.

OPAL_PARTIAL
  Platform can not reset all requested CPUs at this time. This requires
  platform-specific code to work around, otherwise to be treated as
  failure. No CPUs are reset.

OPAL_UNSUPPORTED
  This processor/platform is not supported.


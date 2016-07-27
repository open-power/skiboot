OPAL_SET_XIVE
=============
::

   #define OPAL_SET_XIVE				19

**WARNING:** following documentation is from old sources, and is possibly
not representative of OPALv3 as implemented by skiboot. This should be
used as a starting point for full documentation.

The host calls this function to set the POWER XIVE server and priority
parameters into the PHB XIVE.

Parameters
----------

``phb_id``
  is the value from the PHB node ibm,opal-phbid property.

``xive_number``
  is the index of an XIVE that corresponds to a particular
  interrupt

``service_number``
  is the server (processor) that is to receive the
  interrupt request

``priority``
  is the interrupt priority value applied to the interrupt
  (0=highest, 0xFF = lowest/disabled).


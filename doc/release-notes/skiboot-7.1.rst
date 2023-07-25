.. _skiboot-7.1:

skiboot-7.1
===========

New Features
------------
Removed OPAL calls
^^^^^^^^^^^^^^^^^^
The OPAL_PCI_SET_MVE_ENABLE and OPAL_PCI_SET_MVE calls were removed, as they
were noops. Support for IODA1 and both calls was removed from the Linux kernel
in v6.5-rc1.

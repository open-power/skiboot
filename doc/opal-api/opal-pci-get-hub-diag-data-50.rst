.. _OPAL_PCI_GET_HUB_DIAG_DATA:

OPAL_PCI_GET_HUB_DIAG_DATA
==========================

.. code-block:: c

   #define OPAL_PCI_GET_HUB_DIAG_DATA		50

   enum {
	OPAL_P7IOC_DIAG_TYPE_NONE	= 0,
	OPAL_P7IOC_DIAG_TYPE_RGC	= 1,
	OPAL_P7IOC_DIAG_TYPE_BI		= 2,
	OPAL_P7IOC_DIAG_TYPE_CI		= 3,
	OPAL_P7IOC_DIAG_TYPE_MISC	= 4,
	OPAL_P7IOC_DIAG_TYPE_I2C	= 5,
	OPAL_P7IOC_DIAG_TYPE_LAST	= 6
   };

   struct OpalIoP7IOCErrorData {
	__be16 type;

	/* GEM */
	__be64 gemXfir;
	__be64 gemRfir;
	__be64 gemRirqfir;
	__be64 gemMask;
	__be64 gemRwof;

	/* LEM */
	__be64 lemFir;
	__be64 lemErrMask;
	__be64 lemAction0;
	__be64 lemAction1;
	__be64 lemWof;

	union {
		struct OpalIoP7IOCRgcErrorData {
			__be64 rgcStatus;	/* 3E1C10 */
			__be64 rgcLdcp;		/* 3E1C18 */
		}rgc;
		struct OpalIoP7IOCBiErrorData {
			__be64 biLdcp0;		/* 3C0100, 3C0118 */
			__be64 biLdcp1;		/* 3C0108, 3C0120 */
			__be64 biLdcp2;		/* 3C0110, 3C0128 */
			__be64 biFenceStatus;	/* 3C0130, 3C0130 */

			uint8_t biDownbound;	/* BI Downbound or Upbound */
		}bi;
		struct OpalIoP7IOCCiErrorData {
			__be64 ciPortStatus;	/* 3Dn008 */
			__be64 ciPortLdcp;	/* 3Dn010 */

			uint8_t ciPort;		/* Index of CI port: 0/1 */
		}ci;
	};
   };

   int64_t opal_pci_get_hub_diag_data(uint64_t hub_id, void *diag_buffer, uint64_t diag_buffer_len);

Fetch diagnostic data for an IO hub. Currently, this is only implemented for
p7ioc, which is specific to POWER7, something that was only ever available
internally to IBM for development purposes.

If :ref:`OPAL_PCI_NEXT_ERROR` error type is `OPAL_EEH_IOC_ERROR` and severity
is `OPAL_EEH_SEV_INF`, then the OS should call :ref:`OPAL_PCI_GET_HUB_DIAG_DATA`
to retreive diagnostic data to log appropriately.

Returns
-------
:ref:`OPAL_SUCCESS`
     Diagnostic data copied successfully
:ref:`OPAL_PARAMETER`
     Invalid address, invalid hub ID, or insufficient space in buffer for
     diagnostic data.
:ref:`OPAL_UNSUPPORTED`
     hub doesn't support retreiving diagnostic data.
:ref:`OPAL_CLOSED`
     No pending error.
:ref:`OPAL_INTERNAL_ERROR`
     Something went wrong.

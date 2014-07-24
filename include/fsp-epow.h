/*
 * (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”).
 */

/*
 * Handle FSP EPOW event notifications
 */

#ifndef __FSP_EPOW_H
#define __FSP_EPOW_H

/* FSP based EPOW event notifications */
#define EPOW_NORMAL	0x00	/* panel status normal */
#define EPOW_EX1	0x01	/* panel status extended 1 */
#define EPOW_EX2	0x02	/* Panel status extended 2 */

/* SPCN notifications */
#define SPCN_CNF_CHNG	0x08	/* SPCN configuration change */
#define SPCN_FAULT_LOG	0x04	/* SPCN fault to log */
#define SPCN_POWR_FAIL	0x02	/* SPCN impending power failure */
#define SPCN_INCL_POWR	0x01	/* SPCN incomplete power */

/* EPOW reason code notifications */
#define EPOW_ON_UPS	1	/* System on UPS */
#define EPOW_TMP_AMB	2	/* Over ambient temperature */
#define EPOW_TMP_INT	3	/* Over internal temperature */

#endif

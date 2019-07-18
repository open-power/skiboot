// SPDX-License-Identifier: Apache-2.0
/*
 * OPAL calls to get/set power caps
 *
 * Copyright 2017 IBM Corp.
 */

#include <powercap.h>

static int opal_get_powercap(u32 handle, int token __unused, u32 *pcap)
{
	if (!pcap || !opal_addr_valid(pcap))
		return OPAL_PARAMETER;

	if (powercap_get_class(handle) == POWERCAP_CLASS_OCC)
		return occ_get_powercap(handle, pcap);

	return OPAL_UNSUPPORTED;
};

opal_call(OPAL_GET_POWERCAP, opal_get_powercap, 3);

static int opal_set_powercap(u32 handle, int token, u32 pcap)
{
	if (powercap_get_class(handle) == POWERCAP_CLASS_OCC)
		return occ_set_powercap(handle, token, pcap);

	return OPAL_UNSUPPORTED;
};

opal_call(OPAL_SET_POWERCAP, opal_set_powercap, 3);

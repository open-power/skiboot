/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 * Copyright 2021 IBM Corp.
 */

#ifndef __PAU_H
#define __PAU_H

#include <io.h>
#include <pci.h>
#include <xscom.h>
#include <pau-regs.h>

#define PAU_NBR 6
#define PAU_LINKS_OPENCAPI_PER_PAU 2

enum pau_dev_type {
	PAU_DEV_TYPE_UNKNOWN = 0,
	PAU_DEV_TYPE_OPENCAPI,
	PAU_DEV_TYPE_ANY = INT_MAX
};

struct pau_dev {
	enum pau_dev_type	type;
	uint32_t		index;
	struct dt_node		*dn;

	/* Associated I2C information */
	uint8_t			i2c_bus_id;

	/* Associated PHY information */
	uint32_t		pau_unit; /* 0,3,4,5,6,7 */
	uint32_t		odl_index;
	uint32_t		op_unit; /* 0 -> 7 */
	uint32_t		phy_lane_mask;

	struct pau		*pau;
};

struct pau {
	uint32_t		index;
	struct dt_node		*dt_node;
	uint32_t		chip_id;
	uint64_t		xscom_base;

	/* Global MMIO window (all PAU regs) */
	uint64_t		regs[2];

	struct lock		lock;

	uint32_t		links;
	struct pau_dev		devices[PAU_LINKS_OPENCAPI_PER_PAU];
};

#define PAUDBG(pau, fmt, a...) PAULOG(PR_DEBUG, pau, fmt, ##a)
#define PAUINF(pau, fmt, a...) PAULOG(PR_INFO, pau, fmt, ##a)
#define PAUERR(pau, fmt, a...) PAULOG(PR_ERR, pau, fmt, ##a)

#define PAUDEVDBG(dev, fmt, a...) PAUDEVLOG(PR_DEBUG, dev, fmt, ##a)
#define PAUDEVINF(dev, fmt, a...) PAUDEVLOG(PR_INFO, dev, fmt, ##a)
#define PAUDEVERR(dev, fmt, a...) PAUDEVLOG(PR_ERR, dev, fmt, ##a)

#define PAULOG(l, pau, fmt, a...) \
	prlog(l, "PAU[%d:%d]: " fmt, (pau)->chip_id, (pau)->index, ##a)

#define PAUDEVLOG(l, dev, fmt, a...)		\
	prlog(l, "PAU[%d:%d:%d]: " fmt,		\
	      (dev)->pau->chip_id,		\
	      (dev)->pau->index,		\
	      (dev)->index, ##a)


/* pau-scope index of the link */
static inline uint32_t pau_dev_index(struct pau_dev *dev, int links)
{
	return dev->pau->index * links + dev->index;
}

struct pau_dev *pau_next_dev(struct pau *pau, struct pau_dev *dev,
			       enum pau_dev_type type);

#define pau_for_each_dev_type(dev, pau, type) \
	for (dev = NULL; (dev = pau_next_dev(pau, dev, type));)

#define pau_for_each_opencapi_dev(dev, pau) \
	pau_for_each_dev_type(dev, pau, PAU_DEV_TYPE_OPENCAPI)

#define pau_for_each_dev(dev, pau) \
	pau_for_each_dev_type(dev, pau, PAU_DEV_TYPE_ANY)

#define PAU_PHB_INDEX_BASE	6 /* immediately after real PHBs */
static inline int pau_get_phb_index(unsigned int pau_index,
				    unsigned int link_index)
{
	return PAU_PHB_INDEX_BASE + pau_index * 2 + link_index;
}

#endif /* __PAU_H */

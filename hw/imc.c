/* Copyright 2016 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define pr_fmt(fmt)  "IMC: " fmt
#include <skiboot.h>
#include <xscom.h>
#include <imc.h>
#include <chip.h>
#include <libxz/xz.h>
#include <device.h>

/*
 * Nest IMC PMU names along with their bit values as represented in the
 * imc_chip_avl_vector(in struct imc_chip_cb, look at include/imc.h).
 * nest_pmus[] is an array containing all the possible nest IMC PMU node names.
 */
char const *nest_pmus[] = {
	"powerbus0",
	"mcs0",
	"mcs1",
	"mcs2",
	"mcs3",
	"mcs4",
	"mcs5",
	"mcs6",
	"mcs7",
	"mba0",
	"mba1",
	"mba2",
	"mba3",
	"mba4",
	"mba5",
	"mba6",
	"mba7",
	"cen0",
	"cen1",
	"cen2",
	"cen3",
	"cen4",
	"cen5",
	"cen6",
	"cen7",
	"xlink0",
	"xlink1",
	"xlink2",
	"mcd0",
	"mcd1",
	"phb0",
	"phb1",
	"phb2",
	"resvd",
	"nx",
	"capp0",
	"capp1",
	"vas",
	"int",
	"alink0",
	"alink1",
	"alink2",
	"nvlink0",
	"nvlink1",
	"nvlink2",
	"nvlink3",
	"nvlink4",
	"nvlink5",
	/* reserved bits : 48 - 64 */
};

static char *compress_buf;
static size_t compress_buf_size;
const char **prop_to_fix(struct dt_node *node);
const char *props_to_fix[] = {"events", NULL};

static bool is_nest_mem_initialized(struct imc_chip_cb *ptr)
{
	/*
	 * Non zero value in "Status" field indicate memory initialized.
	 */
	if (!ptr->imc_chip_run_status)
		return false;

	return true;
}

static struct imc_chip_cb *get_imc_cb(uint32_t chip_id)
{
	struct proc_chip *chip = get_chip(chip_id);
	struct imc_chip_cb *cb;

	cb = (struct imc_chip_cb *)(chip->homer_base + P9_CB_STRUCT_OFFSET);
	if (!is_nest_mem_initialized(cb))
		return NULL;

	return cb;
}

/*
 * Decompresses the blob obtained from the IMC pnor sub-partition
 * in "src" of size "src_size", assigns the uncompressed device tree
 * binary to "dst" and returns.
 *
 * Returns 0 on success and -1 on error.
 *
 * TODO: Ideally this should be part of generic subpartition load
 * infrastructure. And decompression can be queued as another CPU job
 */
static int decompress(void *dst, size_t dst_size, void *src, size_t src_size)
{
	struct xz_dec *s;
	struct xz_buf b;
	int ret = 0;

	/* Initialize the xz library first */
	xz_crc32_init();
	s = xz_dec_init(XZ_SINGLE, 0);
	if (s == NULL) {
		prerror("initialization error for xz\n");
		return -1;
	}

	/*
	 * Source address : src
	 * Source size : src_size
	 * Destination address : dst
	 * Destination size : dst_src
	 */
	b.in = src;
	b.in_pos = 0;
	b.in_size = src_size;
	b.out = dst;
	b.out_pos = 0;
	b.out_size = dst_size;

	/* Start decompressing */
	ret = xz_dec_run(s, &b);
	if (ret != XZ_STREAM_END) {
		prerror("failed to decompress subpartition\n");
		ret = -1;
		goto err;
	}

	return 0;
err:
	/* Clean up memory */
	xz_dec_end(s);
	return ret;
}

/*
 * Function return list of properties names for the fixup
 */
const char **prop_to_fix(struct dt_node *node)
{
	if (dt_node_is_compatible(node, "ibm,imc-counters"))
		return props_to_fix;

	return NULL;
}

/* Helper to get the IMC device type for a device node */
static int get_imc_device_type(struct dt_node *node)
{
	const struct dt_property *type;
	u32 val=0;

	if (!node)
		return -1;

	type = dt_find_property(node, "type");
	if (!type)
		return -1;

	val = dt_prop_get_u32(node, "type");
	switch (val){
	case IMC_COUNTER_CHIP:
		return IMC_COUNTER_CHIP;
	case IMC_COUNTER_CORE:
		return IMC_COUNTER_CORE;
	case IMC_COUNTER_THREAD:
		return IMC_COUNTER_THREAD;
	default:
		break;
	}

	/* Unknown/Unsupported IMC device type */
	return -1;
}

static bool is_nest_node(struct dt_node *node)
{
	if (get_imc_device_type(node) == IMC_COUNTER_CHIP)
		return true;

	return false;
}

static bool is_imc_device_type_supported(struct dt_node *node)
{
	u32 val = get_imc_device_type(node);

	if ((val == IMC_COUNTER_CHIP) || (val == IMC_COUNTER_CORE) ||
						(val == IMC_COUNTER_THREAD))
		return true;

	return false;
}

/*
 * Helper to check for the imc device type in the incoming device tree.
 * Remove unsupported device node.
 */
static void check_imc_device_type(struct dt_node *dev)
{
	struct dt_node *node;

	dt_for_each_compatible(dev, node, "ibm,imc-counters") {
		if (!is_imc_device_type_supported(node)) {
			/*
			 * ah nice, found a device type which I didnt know.
			 * Remove it and also mark node as NULL, since dt_next
			 * will try to fetch info for "prev" which is removed
			 * by dt_free.
			 */
			dt_free(node);
			node = NULL;
		}
	}

	return;
}

/*
 * Remove the PMU device nodes from the incoming new subtree, if they are not
 * available in the hardware. The availability is described by the
 * control block's imc_chip_avl_vector.
 * Each bit represents a device unit. If the device is available, then
 * the bit is set else its unset.
 */
static void disable_unavailable_units(struct dt_node *dev)
{
	uint64_t avl_vec;
	struct imc_chip_cb *cb;
	struct dt_node *target;
	int i;

	/* Fetch the IMC control block structure */
	cb = get_imc_cb(this_cpu()->chip_id);
	if (cb)
		avl_vec = be64_to_cpu(cb->imc_chip_avl_vector);
	else
		avl_vec = 0; /* Remove only nest imc device nodes */

	for (i = 0; i < MAX_NEST_UNITS; i++) {
		if (!(PPC_BITMASK(i, i) & avl_vec)) {
			/* Check if the device node exists */
			target = dt_find_by_name(dev, nest_pmus[i]);
			if (!target)
				continue;
			/* Remove the device node */
			dt_free(target);
		}
	}

	return;
}

/*
 * Function to queue the loading of imc catalog data
 * from the IMC pnor partition.
 */
void imc_catalog_preload(void)
{
	uint32_t pvr = (mfspr(SPR_PVR) & ~(0xf000));
	int ret = OPAL_SUCCESS;
	compress_buf_size = MAX_COMPRESSED_IMC_DTB_SIZE;

	/* Enable only for power 9 */
	if (proc_gen != proc_gen_p9)
		return;

	compress_buf = malloc(MAX_COMPRESSED_IMC_DTB_SIZE);
	if (!compress_buf) {
		prerror("Memory allocation for catalog failed\n");
		return;
	}

	ret = start_preload_resource(RESOURCE_ID_IMA_CATALOG,
					pvr, compress_buf, &compress_buf_size);
	if (ret != OPAL_SUCCESS) {
		prerror("Failed to load IMA_CATALOG: %d\n", ret);
		free(compress_buf);
		compress_buf = NULL;
	}

	return;
}

static void imc_dt_update_nest_node(struct dt_node *dev)
{
	struct proc_chip *chip;
	uint64_t *base_addr = NULL;
	uint32_t *chipids = NULL;
	int i=0, nr_chip = nr_chips();
	struct dt_node *node;
	const struct dt_property *type;

	/* Add the base_addr and chip-id properties for the nest node */
	base_addr = malloc(sizeof(uint64_t) * nr_chip);
	chipids = malloc(sizeof(uint32_t) * nr_chip);
	for_each_chip(chip) {
		base_addr[i] = chip->homer_base;
		chipids[i] = chip->id;
		i++;
	}

	dt_for_each_compatible(dev, node, "ibm,imc-counters") {
		type = dt_find_property(node, "type");
		if (type && is_nest_node(node)) {
			dt_add_property(node, "base-addr", base_addr, (i * sizeof(u64)));
			dt_add_property(node, "chip-id", chipids, (i * sizeof(u32)));
		}
	}
}

/*
 * Load the IMC pnor partition and find the appropriate sub-partition
 * based on the platform's PVR.
 * Decompress the sub-partition and link the imc device tree to the
 * existing device tree.
 */
void imc_init(void)
{
	void *decompress_buf;
	uint32_t pvr = (mfspr(SPR_PVR) & ~(0xf000));
	struct dt_node *dev;
	int ret;

	/* Enable only for power 9 */
	if (proc_gen != proc_gen_p9)
		return;

	/* Check we succeeded in starting the preload */
	if (compress_buf == NULL)
		return;

	ret = wait_for_resource_loaded(RESOURCE_ID_IMA_CATALOG, pvr);
	if (ret != OPAL_SUCCESS) {
		prerror("IMC Catalog load failed\n");
		return;
	}

	/*
	 * Flow of the data from PNOR to main device tree:
	 *
	 * PNOR -> compressed local buffer (compress_buf)
	 * compressed local buffer -> decompressed local buf (decompress_buf)
	 * decompress local buffer -> main device tree
	 * free compressed local buffer
	 */

	/*
	 * Memory for decompression.
	 */
	decompress_buf = malloc(MAX_DECOMPRESSED_IMC_DTB_SIZE);
	if (!decompress_buf) {
		prerror("No memory for decompress_buf \n");
		goto err;
	}

	/*
	 * Decompress the compressed buffer
	 */
	ret = decompress(decompress_buf, MAX_DECOMPRESSED_IMC_DTB_SIZE,
				compress_buf, compress_buf_size);
	if (ret < 0)
		goto err;

	/* Create a device tree entry for imc counters */
	dev = dt_new_root("imc-counters");
	if (!dev)
		goto err;

	/*
	 * Attach the new decompress_buf to the imc-counters node.
	 * dt_expand_node() does sanity checks for fdt_header, piggyback
	 */
	ret = dt_expand_node(dev, decompress_buf, 0);
	if (ret < 0) {
		dt_free(dev);
		goto err;
	}

	/* Check and remove unsupported imc device types */
	check_imc_device_type(dev);

	/*
	 * Check and remove unsupported nest unit nodes by the microcode,
	 * from the incoming device tree.
	 */
	disable_unavailable_units(dev);

	/* Fix the phandle in the incoming device tree */
	dt_adjust_subtree_phandle(dev, prop_to_fix);

	/* Update the base_addr and chip-id for nest nodes */
	imc_dt_update_nest_node(dev);

	/*
	 * If the dt_attach_root() fails, "imc-counters" node will not be
	 * seen in the device-tree and hence OS should not make any
	 * OPAL_IMC_* calls.
	 */
	if (!dt_attach_root(dt_root, dev)) {
		dt_free(dev);
		goto err;
	}

	free(compress_buf);
	return;
err:
	prerror("IMC Devices not added\n");
	free(decompress_buf);
	free(compress_buf);
}

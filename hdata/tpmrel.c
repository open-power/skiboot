/* Copyright 2013-2017 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef pr_fmt
#define pr_fmt(fmt) "TPMREL: " fmt
#endif

#include <skiboot.h>
#include <device.h>

#include "spira.h"
#include "hdata.h"
#include "hdif.h"

static void tpmrel_add_firmware_event_log(const struct HDIF_common_hdr *hdif_hdr)
{
	const struct secureboot_tpm_info *stinfo;
	struct dt_node *xscom, *node;
	uint64_t addr;
	int count, i;
	unsigned int asize;

	/* Are the hdat values populated? */
	if (!HDIF_get_idata(hdif_hdr, TPMREL_IDATA_SECUREBOOT_TPM_INFO, &asize))
		return;
	if (asize < sizeof(struct HDIF_array_hdr)) {
		prlog(PR_ERR, "secureboot_tpm_info idata not populated\n");
		return;
	}

	count = HDIF_get_iarray_size(hdif_hdr, TPMREL_IDATA_SECUREBOOT_TPM_INFO);
	if (count > 1) {
		prlog(PR_ERR, "multiple TPM not supported, count=%d\n", count);
		return;
	}

	/*
	 * There can be multiple secureboot_tpm_info entries with each entry
	 * corresponding to a master processor that has a tpm device.
	 * This looks for the tpm node that supposedly exists under the xscom
	 * node associated with the respective chip_id.
	 */
	for (i = 0; i < count; i++) {

		stinfo = HDIF_get_iarray_item(hdif_hdr,
					      TPMREL_IDATA_SECUREBOOT_TPM_INFO,
					      i, NULL);

		xscom = find_xscom_for_chip(be32_to_cpu(stinfo->chip_id));
		if (xscom) {
			dt_for_each_node(xscom, node) {
				if (dt_has_node_property(node, "label", "tpm"))
					break;
			}

			if (node) {
				addr = (uint64_t) stinfo +
					be32_to_cpu(stinfo->srtm_log_offset);
				dt_add_property_u64s(node, "linux,sml-base", addr);
				dt_add_property_cells(node, "linux,sml-size",
						      be32_to_cpu(stinfo->srtm_log_size));

				if (stinfo->tpm_status == TPM_PRESENT_AND_NOT_FUNCTIONAL)
					dt_add_property_string(node, "status", "disabled");
			} else {
				/**
				 * @fwts-label HDATNoTpmForChipId
				 * @fwts-advice HDAT secureboot_tpm_info
				 * structure described a chip id, but no tpm
				 * node was found under that xscom chip id.
				 * This is most certainly a hostboot bug.
				 */
				prlog(PR_ERR, "TPM node not found for "
				      "chip_id=%d (HB bug)\n", stinfo->chip_id);
				continue;
			}
		} else {
			/**
			 * @fwts-label HDATBadChipIdForTPM
			 * @fwts-advice HDAT secureboot_tpm_info structure
			 * described a chip id, but the xscom node for the
			 * chip_id was not found.
			 * This is most certainly a firmware bug.
			 */
			prlog(PR_ERR, "xscom node not found for chip_id=%d\n",
			      stinfo->chip_id);
			continue;
		}
	}
}

void node_stb_parse(void)
{
	struct HDIF_common_hdr *hdif_hdr;

	hdif_hdr = get_hdif(&spira.ntuples.node_stb_data, "TPMREL");
	if (!hdif_hdr) {
		prlog(PR_DEBUG, "TPMREL data not found\n");
		return;
	}

	tpmrel_add_firmware_event_log(hdif_hdr);
}

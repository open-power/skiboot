/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <skiboot.h>
#include <opal.h>
#include <opal-msg.h>
#include <processor.h>

/*
 * HMER register layout:
 * +===+==========+============================+========+===================+
 * |Bit|Name      |Description                 |PowerKVM|Action             |
 * |   |          |                            |HMI     |                   |
 * |   |          |                            |enabled |                   |
 * |   |          |                            |for this|                   |
 * |   |          |                            |bit ?   |                   |
 * +===+==========+============================+========+===================+
 * |0  |malfunctio|A processor core in the     |Yes     |Raise attn from    |
 * |   |n_allert  |system has checkstopped     |        |sapphire resulting |
 * |   |          |(failed recovery) and has   |        |xstop              |
 * |   |          |requested a CP Sparing      |        |                   |
 * |   |          |to occur. This is           |        |                   |
 * |   |          |broadcasted to every        |        |                   |
 * |   |          |processor in the system     |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |1  |Reserved  |reserved                    |n/a     |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |2  |proc_recv_|Processor recovery occurred |Yes     |Log message and    |
 * |   |done      |error-bit in fir not masked |        |continue working.  |
 * |   |          |(see bit 11)                |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |3  |proc_recv_|Processor went through      |Yes     |Log message and    |
 * |   |error_mask|recovery for an error which |        |continue working.  |
 * |   |ed        |is actually masked for      |        |                   |
 * |   |          |reporting                   |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |4  |          |Timer facility experienced  |Yes     |Raise attn from    |
 * |   |tfac_error|an error.                   |        |sapphire resulting |
 * |   |          |TB, DEC, HDEC, PURR or SPURR|        |xstop              |
 * |   |          |may be corrupted (details in|        |                   |
 * |   |          |TFMR)                       |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |5  |          |TFMR SPR itself is          |Yes     |Raise attn from    |
 * |   |tfmr_parit|corrupted.                  |        |sapphire resulting |
 * |   |y_error   |Entire timing facility may  |        |xstop              |
 * |   |          |be compromised.             |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |6  |ha_overflo| UPS (Uniterrupted Power    |No      |N/A                |
 * |   |w_warning |System) Overflow indication |        |                   |
 * |   |          |indicating that the UPS     |        |                   |
 * |   |          |DirtyAddrTable has          |        |                   |
 * |   |          |reached a limit where it    |        |                   |
 * |   |          |requires PHYP unload support|        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |7  |reserved  |reserved                    |n/a     |n/a                |
 * |---+----------+----------------------------+--------+-------------------|
 * |8  |xscom_fail|An XSCOM operation caused by|No      |We handle it by    |
 * |   |          |a cache inhibited load/store|        |manually reading   |
 * |   |          |from this thread failed. A  |        |HMER register.     |
 * |   |          |trap register is            |        |                   |
 * |   |          |available.                  |        |                   |
 * |   |          |                            |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |9  |xscom_done|An XSCOM operation caused by|No      |We handle it by    |
 * |   |          |a cache inhibited load/store|        |manually reading   |
 * |   |          |from this thread completed. |        |HMER register.     |
 * |   |          |If hypervisor               |        |                   |
 * |   |          |intends to use this bit, it |        |                   |
 * |   |          |is responsible for clearing |        |                   |
 * |   |          |it before performing the    |        |                   |
 * |   |          |xscom operation.            |        |                   |
 * |   |          |NOTE: this bit should always|        |                   |
 * |   |          |be masked in HMEER          |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |10 |reserved  |reserved                    |n/a     |n/a                |
 * |---+----------+----------------------------+--------+-------------------|
 * |11 |proc_recv_|Processor recovery occurred |y       |Log message and    |
 * |   |again     |again before bit2 or bit3   |        |continue working.  |
 * |   |          |was cleared                 |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |12-|reserved  |was temperature sensor      |n/a     |n/a                |
 * |15 |          |passed the critical point on|        |                   |
 * |   |          |the way up                  |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |16 |          |SCOM has set a reserved FIR |No      |n/a                |
 * |   |scom_fir_h|bit to cause recovery       |        |                   |
 * |   |m         |                            |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |17 |trig_fir_h|Debug trigger has set a     |No      |n/a                |
 * |   |mi        |reserved FIR bit to cause   |        |                   |
 * |   |          |recovery                    |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |18 |reserved  |reserved                    |n/a     |n/a                |
 * |---+----------+----------------------------+--------+-------------------|
 * |19 |reserved  |reserved                    |n/a     |n/a                |
 * |---+----------+----------------------------+--------+-------------------|
 * |20 |hyp_resour|A hypervisor resource error |y       |Raise attn from    |
 * |   |ce_err    |occurred: data parity error |        |sapphire resulting |
 * |   |          |on, SPRC0:3; SPR_Modereg or |        |xstop.             |
 * |   |          |HMEER.                      |        |                   |
 * |   |          |Note: this bit will cause an|        |                   |
 * |   |          |check_stop when (HV=1, PR=0 |        |                   |
 * |   |          |and EE=0)                   |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |21-|          |if bit 8 is active, the     |No      |We handle it by    |
 * |23 |xscom_stat|reason will be detailed in  |        |Manually reading   |
 * |   |us        |these bits. see chapter 11.1|        |HMER register.     |
 * |   |          |This bits are information   |        |                   |
 * |   |          |only and always masked      |        |                   |
 * |   |          |(mask = '0')                |        |                   |
 * |   |          |If hypervisor intends to use|        |                   |
 * |   |          |this bit, it is responsible |        |                   |
 * |   |          |for clearing it before      |        |                   |
 * |   |          |performing the xscom        |        |                   |
 * |   |          |operation.                  |        |                   |
 * |---+----------+----------------------------+--------+-------------------|
 * |24-|Not       |Not implemented             |n/a     |n/a                |
 * |63 |implemente|                            |        |                   |
 * |   |d         |                            |        |                   |
 * +-- +----------+----------------------------+--------+-------------------+
 *
 * Above HMER bits can be enabled/disabled by modifying
 * SPR_HMEER_HMI_ENABLE_MASK #define in include/processor.h
 * If you modify support for any of the bits listed above, please make sure
 * you change the above table to refelct that.
 *
 * NOTE: Per Dave Larson, never enable 8,9,21-23
 */

int handle_hmi_exception(uint64_t hmer, struct OpalHMIEvent *hmi_evt)
{
	int recover = 1;

	printf("HMI: Received HMI interrupt: HMER = 0x%016llx\n", hmer);
	if (hmi_evt)
		hmi_evt->hmer = hmer;
	if (hmer & SPR_HMER_PROC_RECV_DONE) {
		hmer &= ~SPR_HMER_PROC_RECV_DONE;
		if (hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_NO_ERROR;
			hmi_evt->type = OpalHMI_ERROR_PROC_RECOV_DONE;
		}
		printf("HMI: Processor recovery Done.\n");
	}
	if (hmer & SPR_HMER_PROC_RECV_ERROR_MASKED) {
		hmer &= ~SPR_HMER_PROC_RECV_ERROR_MASKED;
		if (hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_NO_ERROR;
			hmi_evt->type = OpalHMI_ERROR_PROC_RECOV_MASKED;
		}
		printf("HMI: Processor recovery Done (masked).\n");
	}
	if (hmer & SPR_HMER_PROC_RECV_AGAIN) {
		hmer &= ~SPR_HMER_PROC_RECV_AGAIN;
		if (hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_NO_ERROR;
			hmi_evt->type = OpalHMI_ERROR_PROC_RECOV_DONE_AGAIN;
		}
		printf("HMI: Processor recovery occurred again before"
			"bit2 was cleared\n");
	}
	/* Assert if we see malfunction alert, we can not continue. */
	if (hmer & SPR_HMER_MALFUNCTION_ALERT) {
		hmer &= ~SPR_HMER_MALFUNCTION_ALERT;
		if (hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_FATAL;
			hmi_evt->type = OpalHMI_ERROR_MALFUNC_ALERT;
		}
		recover = 0;
	}

	/* Assert if we see Hypervisor resource error, we can not continue. */
	if (hmer & SPR_HMER_HYP_RESOURCE_ERR) {
		hmer &= ~SPR_HMER_HYP_RESOURCE_ERR;
		if (hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_FATAL;
			hmi_evt->type = OpalHMI_ERROR_HYP_RESOURCE;
		}
		recover = 0;
	}

	/*
	 * Assert for now for all TOD errors. In future we need to decode
	 * TFMR and take corrective action wherever required.
	 */
	if (hmer & SPR_HMER_TFAC_ERROR) {
		hmer &= ~SPR_HMER_TFAC_ERROR;
		if (hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_ERROR_SYNC;
			hmi_evt->type = OpalHMI_ERROR_TFAC;
			hmi_evt->tfmr = mfspr(SPR_TFMR);
		}
		recover = 0;
	}
	if (hmer & SPR_HMER_TFMR_PARITY_ERROR) {
		hmer &= ~SPR_HMER_TFMR_PARITY_ERROR;
		if (hmi_evt) {
			hmi_evt->severity = OpalHMI_SEV_FATAL;
			hmi_evt->type = OpalHMI_ERROR_TFMR_PARITY;
			hmi_evt->tfmr = mfspr(SPR_TFMR);
		}
		recover = 0;
	}

	/*
	 * HMER bits are sticky, once set to 1 they remain set to 1 until
	 * they are set to 0. Reset the error source bit to 0, otherwise
	 * we keep getting HMI interrupt again and again.
	 */
	mtspr(SPR_HMER, hmer);
	return recover;
}

static int queue_hmi_event(struct OpalHMIEvent *hmi_evt)
{
	uint64_t *hmi_data;

	/*
	 * struct OpalHMIEvent is of (3 * 64 bits) size and well packed
	 * structure. Hence use uint64_t pointer to pass entire structure
	 * using 4 params in generic message format.
	 */
	hmi_data = (uint64_t *)hmi_evt;

	/* queue up for delivery to host. */
	return opal_queue_msg(OPAL_MSG_HMI_EVT, NULL, NULL,
				hmi_data[0], hmi_data[1], hmi_data[2]);
}

static int64_t opal_handle_hmi(void)
{
	uint64_t hmer;
	int rc = OPAL_SUCCESS;
	struct OpalHMIEvent hmi_evt;
	int recover;

	memset(&hmi_evt, 0, sizeof(struct OpalHMIEvent));
	hmi_evt.version = OpalHMIEvt_V1;

	hmer = mfspr(SPR_HMER);		/* Get HMER register value */
	recover = handle_hmi_exception(hmer, &hmi_evt);

	if (recover)
		hmi_evt.disposition = OpalHMI_DISPOSITION_RECOVERED;
	else
		hmi_evt.disposition = OpalHMI_DISPOSITION_NOT_RECOVERED;

	rc = queue_hmi_event(&hmi_evt);
	return rc;
}
opal_call(OPAL_HANDLE_HMI, opal_handle_hmi, 0);

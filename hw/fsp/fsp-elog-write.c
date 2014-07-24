/* Copyright 2013-2014 IBM Corp.
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


/*
 * This code will enable generation and pushing of error log
 * from powernv, sapphire to FSP
 * Critical events from sapphire that needs to be reported
 * will be pushed on to FSP after converting the
 * error log to Platform Error Log (PEL) format.
 * This is termed as WRITE action to FSP.
 */

#include <skiboot.h>
#include <fsp.h>
#include <cpu.h>
#include <lock.h>
#include <errno.h>
#include <fsp-elog.h>
#include <timebase.h>

/*
 * Maximum number buffers that are pre-allocated
 * to hold elogs that are reported on Sapphire and
 * powernv.
 */
#define ELOG_WRITE_MAX_RECORD		64

static LIST_HEAD(elog_write_to_fsp_pending);
static LIST_HEAD(elog_write_free);

static struct lock elog_write_lock = LOCK_UNLOCKED;
static struct lock elog_panic_write_lock = LOCK_UNLOCKED;

/* Platform Log ID as per the spec */
static uint32_t sapphire_elog_id = 0xB0000000;
static uint32_t powernv_elog_id = 0xB1000000;

/* log buffer  to copy FSP log for READ */
#define ELOG_WRITE_TO_FSP_BUFFER_SIZE	0x00040000
static void *elog_write_to_fsp_buffer;

#define ELOG_PANIC_WRITE_BUFFER_SIZE	0x0010000
static void *elog_panic_write_buffer;

#define ELOG_WRITE_TO_HOST_BUFFER_SIZE	0x0010000
static void *elog_write_to_host_buffer;

struct opal_errorlog *panic_write_buffer;
static int panic_write_buffer_valid;
static uint32_t elog_write_retries;
/* Manipulate this only with write_lock held */
static uint32_t elog_plid_fsp_commit = -1;

/* Need forward declaration because of Circular dependency */
static int create_opal_event(struct opal_errorlog *elog_data, char *pel_buffer);
static int opal_send_elog_to_fsp(void);

void log_error(struct opal_err_info *e_info, void *data, uint16_t size,
	       const char *fmt, ...)
{
	struct opal_errorlog *buf;
	int tag = 0x44455343;  /* ASCII of DESC */
	va_list list;
	char err_msg[250];

	va_start(list, fmt);
	vsnprintf(err_msg, sizeof(err_msg), fmt, list);
	va_end(list);

	/* Log the error on to Sapphire console */
	prerror("%s", err_msg);

	buf = opal_elog_create(e_info);
	if (buf == NULL)
		prerror("ELOG: Error getting buffer to log error\n");
	else {
		opal_elog_update_user_dump(buf, err_msg, tag, strlen(err_msg));
		/* Append any number of call out dumps */
		if (e_info->call_out)
			e_info->call_out(buf, data, size);
		if (elog_fsp_commit(buf))
			prerror("ELOG: Re-try error logging\n");
	}
}


void log_simple_error(struct opal_err_info *e_info, const char *fmt, ...)
{
	struct opal_errorlog *buf;
	int tag = 0x44455343;  /* ASCII of DESC */
	va_list list;
	char err_msg[250];

	va_start(list, fmt);
	vsnprintf(err_msg, sizeof(err_msg), fmt, list);
	va_end(list);

	/* Log the error on to Sapphire console */
	prerror("%s", err_msg);

	buf = opal_elog_create(e_info);
	if (buf == NULL)
		prerror("ELOG: Error getting buffer to log error\n");
	else {
		opal_elog_update_user_dump(buf, err_msg, tag, strlen(err_msg));
		if (elog_fsp_commit(buf))
			prerror("ELOG: Re-try error logging\n");
	}
}

static struct opal_errorlog *get_write_buffer(int opal_event_severity)
{
	struct opal_errorlog *buf;

	lock(&elog_write_lock);
	if (list_empty(&elog_write_free)) {
		unlock(&elog_write_lock);
		if (opal_event_severity == OPAL_ERROR_PANIC) {
			lock(&elog_panic_write_lock);
			if (panic_write_buffer_valid == 0) {
				buf = (struct opal_errorlog *)
						panic_write_buffer;
				panic_write_buffer_valid = 1; /* In Use */
				unlock(&elog_panic_write_lock);
			} else {
				unlock(&elog_panic_write_lock);
				prerror("ELOG: Write buffer full. Retry later\n");
				return NULL;
			}
		} else {
			prerror("ELOG: Write buffer list is full. Retry later\n");
			return NULL;
		}
	} else {
		buf = list_pop(&elog_write_free, struct opal_errorlog, link);
		unlock(&elog_write_lock);
	}

	memset(buf, 0, sizeof(struct opal_errorlog));
	return buf;
}

/* Reporting of error via struct opal_errorlog */
struct opal_errorlog *opal_elog_create(struct opal_err_info *e_info)
{
	struct opal_errorlog *buf;

	buf = get_write_buffer(e_info->sev);
	if (buf) {
		buf->error_event_type = e_info->err_type;
		buf->component_id = e_info->cmp_id;
		buf->subsystem_id = e_info->subsystem;
		buf->event_severity = e_info->sev;
		buf->event_subtype = e_info->event_subtype;
		buf->reason_code = e_info->reason_code;
		buf->elog_origin = ORG_SAPPHIRE;

		lock(&elog_write_lock);
		buf->plid = ++sapphire_elog_id;
		unlock(&elog_write_lock);
	}

	return buf;
}

static void remove_elog_head_entry(void)
{
	struct opal_errorlog *head, *entry;

	lock(&elog_write_lock);
	if (!list_empty(&elog_write_to_fsp_pending)) {
		head = list_top(&elog_write_to_fsp_pending,
					struct opal_errorlog, link);
		if (head->plid == elog_plid_fsp_commit) {
			entry = list_pop(&elog_write_to_fsp_pending,
					struct opal_errorlog, link);
			list_add_tail(&elog_write_free, &entry->link);
			/* Reset the counter */
			elog_plid_fsp_commit = -1;
		}
	}
	elog_write_retries = 0;
	unlock(&elog_write_lock);
}

static void opal_fsp_write_complete(struct fsp_msg *read_msg)
{
	uint8_t val;

	val = (read_msg->resp->word1 >> 8) & 0xff;
	fsp_freemsg(read_msg);

	switch (val) {
	case FSP_STATUS_SUCCESS:
			remove_elog_head_entry();
			break;

	default:
		if (elog_write_retries++ >= MAX_RETRIES) {
			remove_elog_head_entry();
			prerror("ELOG: Error in writing to FSP!\n");
		}
		break;
	}

	if (opal_send_elog_to_fsp() != OPAL_SUCCESS)
		prerror("ELOG: Error sending elog to FSP !\n");
}

/* write PEL format hex dump of the log to FSP */
static int64_t fsp_opal_elog_write(size_t opal_elog_size)
{
	struct fsp_msg *elog_msg;

	elog_msg = fsp_mkmsg(FSP_CMD_CREATE_ERRLOG, 3, opal_elog_size,
						 0, PSI_DMA_ERRLOG_WRITE_BUF);
	if (!elog_msg) {
		prerror("ELOG: Failed to create message for WRITE to FSP\n");
		return OPAL_INTERNAL_ERROR;
	}
	if (fsp_queue_msg(elog_msg, opal_fsp_write_complete)) {
		fsp_freemsg(elog_msg);
		elog_msg = NULL;
		prerror("FSP: Error queueing elog update\n");
		return OPAL_INTERNAL_ERROR;
	}
	return OPAL_SUCCESS;
}

static int opal_send_elog_to_fsp(void)
{
	struct opal_errorlog *head;
	int rc = OPAL_SUCCESS;

	/* Convert entry to PEL
	 * and push it down to FSP. We wait for the ack from
	 * FSP.
	 */
	lock(&elog_write_lock);
	if (!list_empty(&elog_write_to_fsp_pending)) {
		head = list_top(&elog_write_to_fsp_pending,
					 struct opal_errorlog, link);
		elog_plid_fsp_commit = head->plid;
		head->log_size = create_opal_event(head,
					(char *)elog_write_to_fsp_buffer);
		rc = fsp_opal_elog_write(head->log_size);
		unlock(&elog_write_lock);
		return rc;
	}
	unlock(&elog_write_lock);
	return rc;
}

static int opal_push_logs_sync_to_fsp(struct opal_errorlog *buf)
{
	struct fsp_msg *elog_msg;
	int opal_elog_size = 0;
	int rc = OPAL_SUCCESS;

	lock(&elog_panic_write_lock);
	opal_elog_size = create_opal_event(buf,
				(char *)elog_panic_write_buffer);

	elog_msg = fsp_mkmsg(FSP_CMD_CREATE_ERRLOG, 3, opal_elog_size,
					0, PSI_DMA_ELOG_PANIC_WRITE_BUF);
	if (!elog_msg) {
		prerror("ELOG: PLID: 0x%x Failed to create message for WRITE "
							"to FSP\n", buf->plid);
		unlock(&elog_panic_write_lock);
		return OPAL_INTERNAL_ERROR;
	}

	if (fsp_sync_msg(elog_msg, false)) {
		fsp_freemsg(elog_msg);
		rc = OPAL_INTERNAL_ERROR;
	} else {
		rc = (elog_msg->resp->word1 >> 8) & 0xff;
		fsp_freemsg(elog_msg);
	}

	if ((buf == panic_write_buffer) && (panic_write_buffer_valid == 1)) {
		panic_write_buffer_valid = 0;
		unlock(&elog_panic_write_lock);
	} else {
		/* buffer got from the elog_write list , put it back */
		unlock(&elog_panic_write_lock);
		lock(&elog_write_lock);
		list_add_tail(&elog_write_free, &buf->link);
		unlock(&elog_write_lock);
	}
	return rc;
}

static inline u64 get_elog_timeout(void)
{
	return (mftb() + secs_to_tb(ERRORLOG_TIMEOUT_INTERVAL));
}

int elog_fsp_commit(struct opal_errorlog *buf)
{
	int rc = OPAL_SUCCESS;

	/* Error needs to be committed, update the time out value */
	buf->elog_timeout = get_elog_timeout();

	if (buf->event_severity == OPAL_ERROR_PANIC) {
		rc = opal_push_logs_sync_to_fsp(buf);
		return rc;
	}

	lock(&elog_write_lock);
	if (list_empty(&elog_write_to_fsp_pending)) {
		list_add_tail(&elog_write_to_fsp_pending, &buf->link);
		unlock(&elog_write_lock);
		rc = opal_send_elog_to_fsp();
		return rc;
	}
	list_add_tail(&elog_write_to_fsp_pending, &buf->link);
	unlock(&elog_write_lock);
	return rc;
}

/* This function is called from POWERNV to push logs
 * on FSP
 */
static int opal_commit_log_to_fsp(struct opal_errorlog *buf)
{
	struct opal_errorlog *opal_buf;
	int rc = OPAL_SUCCESS;
	uint32_t plid;

	/* Copy the buffer to Sapphire and queue it to push
	 * to FSP and return
	 */
	lock(&elog_write_lock);
	if (list_empty(&elog_write_free)) {
		unlock(&elog_write_lock);
		prerror("ELOG: Error! Write buffer list is full. Retry later\n");
		return -1;
	}
	opal_buf = list_pop(&elog_write_free, struct opal_errorlog, link);
	plid = ++powernv_elog_id;
	unlock(&elog_write_lock);

	memcpy(opal_buf, buf, sizeof(struct opal_errorlog));
	opal_buf->elog_origin = ORG_POWERNV;
	opal_buf->plid = plid;

	rc = elog_fsp_commit(opal_buf);
	return rc;
}

int opal_elog_update_user_dump(struct opal_errorlog *buf, unsigned char *data,
						uint32_t tag, uint16_t size)
{
	char *buffer;
	struct opal_user_data_section *tmp;

	if (!buf) {
		prerror("ELOG: Cannot update user data. Buffer is invalid\n");
		return -1;
	}

	buffer = (char *)buf->user_data_dump + buf->user_section_size;
	if ((buf->user_section_size + size) > OPAL_LOG_MAX_DUMP) {
		prerror("ELOG: Size of dump data overruns buffer\n");
		return -1;
	}

	tmp = (struct opal_user_data_section *)buffer;
	tmp->tag = tag;
	tmp->size = size + sizeof(struct opal_user_data_section) - 1;
	memcpy(tmp->data_dump, data, size);

	buf->user_section_size += tmp->size;
	buf->user_section_count++;
	return 0;
}

/* Create MTMS section for sapphire log */
static void create_mtms_section(struct opal_errorlog *elog_data,
					char *pel_buffer, int *pel_offset)
{
	struct opal_mtms_section *mtms = (struct opal_mtms_section *)
				(pel_buffer + *pel_offset);

	mtms->v6header.id = ELOG_SID_MACHINE_TYPE;
	mtms->v6header.length = MTMS_SECTION_SIZE;
	mtms->v6header.version = OPAL_EXT_HRD_VER;
	mtms->v6header.subtype = 0;
	mtms->v6header.component_id = elog_data->component_id;

	memset(mtms->model, 0x00, sizeof(mtms->model));
	memcpy(mtms->model, dt_prop_get(dt_root, "model"), OPAL_SYS_MODEL_LEN);
	memset(mtms->serial_no, 0x00, sizeof(mtms->serial_no));

	memcpy(mtms->serial_no, dt_prop_get(dt_root, "system-id"),
						 OPAL_SYS_SERIAL_LEN);
	*pel_offset += MTMS_SECTION_SIZE;
}

/* Create extended header section */
static void create_extended_header_section(struct opal_errorlog *elog_data,
					char *pel_buffer, int *pel_offset)
{
	const char  *opalmodel = NULL;
	uint64_t extd_time;

	struct opal_extended_header_section *extdhdr =
			(struct opal_extended_header_section *)
					(pel_buffer + *pel_offset);

	extdhdr->v6header.id = ELOG_SID_EXTENDED_HEADER;
	extdhdr->v6header.length = EXTENDED_HEADER_SECTION_SIZE;
	extdhdr->v6header.version = OPAL_EXT_HRD_VER;
	extdhdr->v6header.subtype = 0;
	extdhdr->v6header.component_id = elog_data->component_id;

	memset(extdhdr->model, 0x00, sizeof(extdhdr->model));
	opalmodel = dt_prop_get(dt_root, "model");
	memcpy(extdhdr->model, opalmodel, OPAL_SYS_MODEL_LEN);

	memset(extdhdr->serial_no, 0x00, sizeof(extdhdr->serial_no));
	memcpy(extdhdr->serial_no, dt_prop_get(dt_root, "system-id"),
							OPAL_SYS_SERIAL_LEN);

	memset(extdhdr->opal_release_version, 0x00,
				sizeof(extdhdr->opal_release_version));
	memset(extdhdr->opal_subsys_version, 0x00,
				sizeof(extdhdr->opal_subsys_version));

	fsp_rtc_get_cached_tod(&extdhdr->extended_header_date, &extd_time);
	extdhdr->extended_header_time = extd_time >> 32;
	extdhdr->opal_symid_len = 0;
	memset(extdhdr->opalsymid, 0x00, sizeof(extdhdr->opalsymid));

	*pel_offset += EXTENDED_HEADER_SECTION_SIZE;
}

/* set src type */
static void settype(struct opal_src_section *src, uint8_t src_type)
{
	char type[4];
	sprintf(type, "%02X", src_type);
	memcpy(src->srcstring, type, 2);
}

/* set SRC subsystem type */
static void setsubsys(struct opal_src_section *src, uint8_t src_subsys)
{
	char subsys[4];
	sprintf(subsys, "%02X", src_subsys);
	memcpy(src->srcstring+2, subsys, 2);
}

/* Ser reason code of SRC */
static void setrefcode(struct opal_src_section *src, uint16_t src_refcode)
{
	char refcode[8];
	sprintf(refcode, "%04X", src_refcode);
	memcpy(src->srcstring+4, refcode, 4);
}

/* Create SRC section of OPAL log */
static void create_src_section(struct opal_errorlog *elog_data,
					char *pel_buffer, int *pel_offset)
{
	struct opal_src_section *src = (struct opal_src_section *)
						(pel_buffer + *pel_offset);

	src->v6header.id = ELOG_SID_PRIMARY_SRC;
	src->v6header.length = SRC_SECTION_SIZE;
	src->v6header.version = OPAL_ELOG_VERSION;
	src->v6header.subtype = OPAL_ELOG_SST;
	src->v6header.component_id = elog_data->component_id;

	src->version = OPAL_SRC_SEC_VER;
	src->flags = 0;
	src->wordcount = OPAL_SRC_MAX_WORD_COUNT;
	src->srclength = SRC_LENGTH;
	settype(src, OPAL_SRC_TYPE_ERROR);
	setsubsys(src, OPAL_FAILING_SUBSYSTEM);
	setrefcode(src, elog_data->reason_code);
	memset(src->hexwords, 0 , (8 * 4));
	src->hexwords[0] = OPAL_SRC_FORMAT;
	src->hexwords[4] = elog_data->additional_info[0];
	src->hexwords[5] = elog_data->additional_info[1];
	src->hexwords[6] = elog_data->additional_info[2];
	src->hexwords[7] = elog_data->additional_info[3];
	*pel_offset += SRC_SECTION_SIZE;
}

/* Create user header section */
static void create_user_header_section(struct opal_errorlog *elog_data,
					char *pel_buffer, int *pel_offset)
{
	struct opal_user_header_section *usrhdr =
				(struct opal_user_header_section *)
						(pel_buffer + *pel_offset);

	usrhdr->v6header.id = ELOG_SID_USER_HEADER;
	usrhdr->v6header.length = USER_HEADER_SECTION_SIZE;
	usrhdr->v6header.version = OPAL_ELOG_VERSION;
	usrhdr->v6header.subtype = OPAL_ELOG_SST;
	usrhdr->v6header.component_id = elog_data->component_id;

	usrhdr->subsystem_id = elog_data->subsystem_id;
	usrhdr->event_scope = 0;
	usrhdr->event_severity = elog_data->event_severity;
	usrhdr->event_type = elog_data->event_subtype;

	if (elog_data->elog_origin == ORG_SAPPHIRE)
		usrhdr->action_flags = ERRL_ACTION_REPORT;
	else
		usrhdr->action_flags = ERRL_ACTION_NONE;

	*pel_offset += USER_HEADER_SECTION_SIZE;
}

/* Create private header section */
static void create_private_header_section(struct opal_errorlog *elog_data,
					char *pel_buffer, int *pel_offset)
{
	uint64_t ctime;
	struct opal_private_header_section *privhdr =
				(struct opal_private_header_section *)
								pel_buffer;

	privhdr->v6header.id = ELOG_SID_PRIVATE_HEADER;
	privhdr->v6header.length = PRIVATE_HEADER_SECTION_SIZE;
	privhdr->v6header.version = OPAL_ELOG_VERSION;
	privhdr->v6header.subtype = OPAL_ELOG_SST;
	privhdr->v6header.component_id = elog_data->component_id;
	privhdr->plid = elog_data->plid;

	fsp_rtc_get_cached_tod(&privhdr->create_date, &ctime);
	privhdr->create_time = ctime >> 32;
	privhdr->section_count = 5;

	privhdr->creator_subid_hi = 0x00;
	privhdr->creator_subid_lo = 0x00;

	if (elog_data->elog_origin == ORG_SAPPHIRE)
		privhdr->creator_id = OPAL_CID_SAPPHIRE;
	else
		privhdr->creator_id = OPAL_CID_POWERNV;

	privhdr->log_entry_id = 0x00;   /* entry id is updated by FSP */

	*pel_offset += PRIVATE_HEADER_SECTION_SIZE;
}

static void create_user_defined_section(struct opal_errorlog *elog_data,
					char *pel_buffer, int *pel_offset)
{
	char *dump = (char *)pel_buffer + *pel_offset;
	char *opal_buf = (char *)elog_data->user_data_dump;
	struct opal_user_section *usrhdr;
	struct opal_user_data_section *opal_usr_data;
	struct opal_private_header_section *privhdr =
			 (struct opal_private_header_section *)pel_buffer;
	int i;

	for (i = 0; i < elog_data->user_section_count; i++) {

		usrhdr = (struct opal_user_section *)dump;
		opal_usr_data = (struct opal_user_data_section *)opal_buf;

		usrhdr->v6header.id = ELOG_SID_USER_DEFINED;
		usrhdr->v6header.version = OPAL_ELOG_VERSION;
		usrhdr->v6header.length = sizeof(struct opal_v6_header) +
							opal_usr_data->size;
		usrhdr->v6header.subtype = OPAL_ELOG_SST;
		usrhdr->v6header.component_id = elog_data->component_id;

		memcpy(usrhdr->dump, opal_buf, opal_usr_data->size);
		*pel_offset += usrhdr->v6header.length;
		dump += usrhdr->v6header.length;
		opal_buf += opal_usr_data->size;
		privhdr->section_count++;
	}
}

/* Create all require section of PEL log and write to TCE buffer */
static int create_opal_event(struct opal_errorlog *elog_data, char *pel_buffer)
{
	int pel_offset = 0;

	memset(pel_buffer, 0, PSI_DMA_ERRLOG_WRITE_BUF_SZ);

	create_private_header_section(elog_data, pel_buffer, &pel_offset);
	create_user_header_section(elog_data, pel_buffer, &pel_offset);
	create_src_section(elog_data, pel_buffer, &pel_offset);
	create_extended_header_section(elog_data, pel_buffer, &pel_offset);
	create_mtms_section(elog_data, pel_buffer, &pel_offset);
	if (elog_data->user_section_count)
		create_user_defined_section(elog_data, pel_buffer, &pel_offset);

	return pel_offset;
}

/* Pre-allocate memory for writing error log to FSP */
static int init_elog_write_free_list(uint32_t num_entries)
{
	struct opal_errorlog *entry;
	int i;

	entry = zalloc(sizeof(struct opal_errorlog) * num_entries);
	if (!entry)
		goto out_err;

	for (i = 0; i < num_entries; ++i) {
		list_add_tail(&elog_write_free, &entry->link);
		entry++;
	}

	/* Pre-allocate one single buffer for PANIC path */
	panic_write_buffer = zalloc(sizeof(struct opal_errorlog));
	if (!panic_write_buffer)
		goto out_err;

	return 0;

out_err:
	return -ENOMEM;
}

/* fsp elog init function */
void fsp_elog_write_init(void)
{
	if (!fsp_present())
		return;

	elog_panic_write_buffer = memalign(TCE_PSIZE,
					   ELOG_PANIC_WRITE_BUFFER_SIZE);
	if (!elog_panic_write_buffer) {
		prerror("FSP: could not allocate ELOG_PANIC_WRITE_BUFFER!\n");
		return;
	}

	elog_write_to_fsp_buffer = memalign(TCE_PSIZE,
						ELOG_WRITE_TO_FSP_BUFFER_SIZE);
	if (!elog_write_to_fsp_buffer) {
		prerror("FSP: could not allocate ELOG_WRITE_BUFFER!\n");
		return;
	}

	elog_write_to_host_buffer = memalign(TCE_PSIZE,
					ELOG_WRITE_TO_HOST_BUFFER_SIZE);
	if (!elog_write_to_host_buffer) {
		prerror("FSP: could not allocate ELOG_WRITE_TO_HOST_BUFFER!\n");
		return;
	}

	/* Map TCEs */
	fsp_tce_map(PSI_DMA_ELOG_PANIC_WRITE_BUF, elog_panic_write_buffer,
					PSI_DMA_ELOG_PANIC_WRITE_BUF_SZ);

	fsp_tce_map(PSI_DMA_ERRLOG_WRITE_BUF, elog_write_to_fsp_buffer,
					PSI_DMA_ERRLOG_WRITE_BUF_SZ);

	fsp_tce_map(PSI_DMA_ELOG_WR_TO_HOST_BUF, elog_write_to_host_buffer,
					PSI_DMA_ELOG_WR_TO_HOST_BUF_SZ);

	/* pre-allocate memory for 64 records */
	if (init_elog_write_free_list(ELOG_WRITE_MAX_RECORD)) {
		prerror("ELOG: Cannot allocate WRITE buffers to log errors!\n");
		return;
	}

	/* register opal Interface */
	opal_register(OPAL_ELOG_SEND, opal_commit_log_to_fsp, 1);
}

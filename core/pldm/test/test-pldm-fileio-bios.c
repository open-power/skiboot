// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// Copyright 2024 IBM Corp.


#include "test-pldm-common.c"

#define TEST_FILE_IO_NAME "81e0066b.lid"
#define TEST_FILE_IO_HANDLE 11
#define TEST_FILE_IO_LENGTH 50
#define TEST_FILE_IO_BUF1 "This is Test buffer Open power Foundation"

#define TEST_BIOS_STRING "hb_lid_ids"
#define TEST_BIOS_STRING_HANDLE 60
#define TEST_ATTR_HANDLE 1
#define TEST_ATTR_STRING_MIN_LEN 0
#define TEST_ATTR_STRING_MAX_LEN 0
#define TEST_ATTR_STRING_DEFAULT_LEN 4
#define TEST_ATTR_STRING_DEFAULT "test"
#define TEST_VALUE_TABLE_CURRENT_STR "ATTR_PERM=81e00663,ATTR_TMP=81e00664,NVRAM=81e0066b"
#define TEST_VALID_ATTR_NAME "ATTR_TMP"

enum bios_special_case_code  {
	NORMAL_CASE = 0x00,
	STRING_TABLE_ERROR = 0x01,
	ATTR_TABLE_ERROR = 0x02,
	VALUE_TABLE_ERROR = 0x03
};
enum bios_special_case_code bios_special_case = NORMAL_CASE;


enum pldm_completion_codes special_reply;


struct blocklevel_device *bl;
void *pldm_file_io_buff[TEST_FILE_IO_LENGTH];

/*
 * This function duplicates BMC functionality for Pldm self test
 * This Genrate Filetable entry for self test
 * The file table contains the list of files available and
 * their attributes.
 *
 * Ex:
 * {
 *   "FileHandle": "11",
 *   "FileNameLength": 12,
 *   "FileName": "81e0066b.lid",
 *   "FileSize": 589824,
 *   "FileTraits": 6
 * }
 */
static uint32_t get_test_filetable_entry(uint8_t **file_attr_table, int *size)
{
	struct pldm_file_attr_table_entry *pldm_file_attr_table_entry;
	uint8_t FileName[] = TEST_FILE_IO_NAME;
	uint32_t file_length = TEST_FILE_IO_LENGTH;

	/* calculate sizeof whole struct */
	*size = sizeof(struct pldm_file_attr_table_entry *) + strlen(FileName)
			+ sizeof(file_length) - 1;
	*file_attr_table = malloc(*size);
	if (*file_attr_table == NULL)
		return OPAL_RESOURCE;

	pldm_file_attr_table_entry = (struct pldm_file_attr_table_entry *)*file_attr_table;
	pldm_file_attr_table_entry->file_handle = TEST_FILE_IO_HANDLE;
	pldm_file_attr_table_entry->file_name_length = strlen(FileName);
	memcpy(pldm_file_attr_table_entry->file_attr_table_nst, FileName,
		strlen(FileName));

	memcpy(pldm_file_attr_table_entry->file_attr_table_nst + strlen(FileName),
			(uint8_t *)&file_length, sizeof(file_length));

	return OPAL_SUCCESS;
}


/*
 * This function duplicates BMC functionality for Pldm self test
 * it tries to handle PLDM_REQUEST for fileio and reply with appropriate PLDM_RESPONSE
 * message
 */
static int pldm_test_reply_request_fileio(void *request_msg, size_t request_len,
			void **response_msg, size_t *response_len)
{
	int rc;
	void *payload_data;
	uint32_t offset;      //!< Offset to file where write starts
	uint32_t length;
	uint32_t file_handle; //!< Handle to file
	int  payload_len = 0;
	size_t file_data_offset = 0;
	struct pldm_write_file_req file_req;
	uint32_t transfer_handle;
	uint8_t transfer_opflag;
	uint8_t table_type;
	uint8_t *file_attr_table;
	uint32_t table_size;
	struct pldm_read_file_resp *response;

	if (((struct pldm_msg *)request_msg)->hdr.type != PLDM_OEM)
		return OPAL_PARAMETER;

	/* check command received and reply with appropriate pldm response message */
	switch (((struct pldm_msg *)request_msg)->hdr.command) {
	case PLDM_GET_FILE_TABLE:

		payload_len = request_len - sizeof(struct pldm_msg_hdr);

		rc = decode_get_file_table_req(request_msg, payload_len,
				&transfer_handle, &transfer_opflag, &table_type);
		if (rc != PLDM_SUCCESS)
			return OPAL_PARAMETER;

		/* Get Filetable entry for self test */
		rc = get_test_filetable_entry(&file_attr_table, &table_size);
		if (rc != OPAL_SUCCESS)
			return OPAL_PARAMETER;

		*response_len = sizeof(struct pldm_msg_hdr)
			+ sizeof(struct pldm_get_file_table_resp)
			+ table_size - 1;
		*response_msg = malloc(*response_len);
		if (*response_msg == NULL)
			return OPAL_RESOURCE;


		rc = encode_get_file_table_resp(
				((struct pldm_msg *)request_msg)->hdr.instance_id,
				PLDM_SUCCESS, PLDM_GET_NEXTPART, PLDM_START_AND_END,
				file_attr_table, table_size, *response_msg);
		if (rc != PLDM_SUCCESS)
			return OPAL_PARAMETER;

		free(file_attr_table);

		break;
	case PLDM_WRITE_FILE:
		payload_len = request_len - sizeof(struct pldm_msg_hdr);

		rc = decode_write_file_req(request_msg, payload_len, &file_handle,
				&offset, &length, &file_data_offset);
		if (rc != PLDM_SUCCESS)
			return OPAL_PARAMETER;

		/*
		 * TEST if file handle received is same as that we send while making
		 * call to pldm request (i.e. TEST_FILE_IO_HANDLE).
		 * then PLDM message are received without any distortion in path.
		 */
		if (file_handle != TEST_FILE_IO_HANDLE)
			return OPAL_PARAMETER;

		payload_data = ((struct pldm_msg *)request_msg)->payload
			+ sizeof(file_req.file_handle)
			+ sizeof(file_req.offset)
			+ sizeof(file_req.length);

		memcpy(pldm_file_io_buff, payload_data, length);

		/*
		 * TEST if file buff received is same as that we send while making
		 * call to pldm request (i.e TEST_FILE_IO_BUF1).
		 * Then PLDM message are transferred without distortion in path.
		 */
		if (strncmp(TEST_FILE_IO_BUF1, (char *)payload_data, length) != 0) {
			perror("PLDM_TEST :strncmp");
			return OPAL_PARAMETER;
		}
		*response_len = sizeof(struct pldm_msg_hdr) +
			sizeof(struct pldm_write_file_resp);
		*response_msg = malloc(*response_len);
		if (*response_msg == NULL)
			return OPAL_RESOURCE;



		if (special_reply != 0) {
			rc = encode_write_file_resp(
					((struct pldm_msg *)request_msg)->hdr.instance_id,
					special_reply, length, *response_msg);
			if (rc != PLDM_SUCCESS)
				return OPAL_PARAMETER;
		} else {
			rc = encode_write_file_resp(
					((struct pldm_msg *)request_msg)->hdr.instance_id,
					PLDM_SUCCESS, length, *response_msg);
			if (rc != PLDM_SUCCESS)
				return OPAL_PARAMETER;
		}
		break;
	case PLDM_READ_FILE:

		payload_len = request_len - sizeof(struct pldm_msg_hdr);
		rc = decode_read_file_req(request_msg, payload_len, &file_handle, &offset,
				&length);

		if (rc != PLDM_SUCCESS)
			return OPAL_PARAMETER;


		/*
		 * TEST : if file handle received is same as that we send while making
		 * call to pldm request (i.e. TEST_FILE_IO_HANDLE).
		 * then PLDM message are transferred without any distortion in path.
		 */
		if (file_handle != TEST_FILE_IO_HANDLE) {
			printf("PLDM_TEST : File Handle not matched");
			return OPAL_PARAMETER;
		}

		/*
		 * check if length + offset < TEST_FILE_IO_LENGTH
		 * so required data length can be readed
		 */
		if (file_handle != TEST_FILE_IO_HANDLE ||
				length + offset > TEST_FILE_IO_LENGTH) {
			perror("TEST : length+offset Invalid");
			return OPAL_PARAMETER;
		}


		*response_len = sizeof(struct pldm_msg_hdr) +
			sizeof(struct pldm_read_file_resp) + length - 1;

		*response_msg = malloc(*response_len);
		if (*response_msg == NULL)
			return OPAL_RESOURCE;

		/*
		 * This will reply PLDM Request
		 * with specific error completion_code
		 * Only for test
		 */
		if (special_reply != 0) {
			rc = encode_read_file_resp(
					((struct pldm_msg *)request_msg)->hdr.instance_id,
					special_reply, length, *response_msg);
			if (rc != PLDM_SUCCESS)
				return OPAL_PARAMETER;
			return OPAL_SUCCESS;
		}

		rc = encode_read_file_resp(((struct pldm_msg *)request_msg)->hdr.instance_id,
				PLDM_SUCCESS, length, *response_msg);
		if (rc != PLDM_SUCCESS)
			return OPAL_PARAMETER;


		response = (struct pldm_read_file_resp *)
			((struct pldm_msg *)*response_msg)->payload;

		/* Copy required buffer to end of PLDM response */
		memcpy(response->file_data, pldm_file_io_buff + offset, length);
		break;


	default:
		return OPAL_PARAMETER;

	}

	return OPAL_SUCCESS;



}

/*
 * This function duplicates BMC functionality for Pldm self test
 * It generate bios table for self test based on input parameter tabletype
 */
static uint32_t get_test_table_entry_bios(uint8_t tableType, uint8_t **bios_table,
		uint32_t *bios_table_length, uint8_t *table_response)
{
	int pad_len = 0;
	uint32_t checksum = 0;
	struct pldm_bios_string_table_entry *string_entry;
	struct pldm_bios_table_attr_entry_string_info info;
	*table_response = PLDM_ERROR;

	switch (tableType) {

	case PLDM_BIOS_STRING_TABLE:
		*bios_table_length = sizeof(struct pldm_bios_string_table_entry)
			+ strlen(TEST_BIOS_STRING) - 1;

		/* calculate padding length */
		if (*bios_table_length % 4)
			pad_len = 4 - (*bios_table_length % 4);
		else
			pad_len = 0;
		*bios_table_length += sizeof(uint32_t) + pad_len;

		*bios_table = malloc(*bios_table_length);
		if (*bios_table == NULL)
			return OPAL_RESOURCE;

		memset(*bios_table, 0, *bios_table_length);

		string_entry = (struct pldm_bios_string_table_entry *)(*bios_table);
		string_entry->string_handle = htole16(TEST_BIOS_STRING_HANDLE);
		string_entry->string_length = htole16(strlen(TEST_BIOS_STRING));
		memcpy(string_entry->name, TEST_BIOS_STRING, string_entry->string_length);
		if (bios_special_case != STRING_TABLE_ERROR)
			*table_response = PLDM_SUCCESS;

		break;
	case PLDM_BIOS_ATTR_TABLE:

		*bios_table_length = sizeof(struct pldm_bios_attr_table_entry)
			+ sizeof(struct attr_table_string_entry_fields)
			+ strlen(TEST_ATTR_STRING_DEFAULT);

		/* calculate padding length */
		if (*bios_table_length % 4)
			pad_len = 4 - (*bios_table_length % 4);
		else
			pad_len = 0;
		*bios_table_length += sizeof(uint32_t) + pad_len;

		*bios_table = malloc(*bios_table_length);
		if (*bios_table == NULL)
			return OPAL_RESOURCE;

		memset(*bios_table, 0, *bios_table_length);

		info.name_handle = TEST_BIOS_STRING_HANDLE;
		info.read_only = 0;
		info.string_type = PLDM_BIOS_STRING;
		info.min_length = TEST_ATTR_STRING_MIN_LEN;
		info.max_length = TEST_ATTR_STRING_MAX_LEN;
		info.def_length = TEST_ATTR_STRING_DEFAULT_LEN;
		info.def_string = malloc(strlen(TEST_ATTR_STRING_DEFAULT));
		if (info.def_string == NULL)
			return OPAL_RESOURCE;

		memcpy((uint8_t *)info.def_string, TEST_ATTR_STRING_DEFAULT,
				strlen(TEST_ATTR_STRING_DEFAULT));
		pldm_bios_table_attr_entry_string_encode(*bios_table, *bios_table_length, &info);

		free((uint8_t *)info.def_string);
		if (bios_special_case != ATTR_TABLE_ERROR) {
			*table_response = PLDM_SUCCESS;
			((struct pldm_bios_attr_table_entry *)*bios_table)->attr_handle =
				TEST_ATTR_HANDLE;
		}
		break;

	case PLDM_BIOS_ATTR_VAL_TABLE:
		*bios_table_length = sizeof(struct pldm_bios_attr_val_table_entry)
			+ sizeof(uint16_t) + sizeof(TEST_VALUE_TABLE_CURRENT_STR) - 1;

		/* calculate padding length */
		if (*bios_table_length % 4)
			pad_len = 4 - (*bios_table_length % 4);
		else
			pad_len = 0;
		*bios_table_length += sizeof(uint32_t) + pad_len;

		*bios_table = malloc(*bios_table_length);
		if (*bios_table == NULL)
			return OPAL_RESOURCE;

		memset(*bios_table, 0, *bios_table_length);

		pldm_bios_table_attr_value_entry_encode_string(*bios_table, *bios_table_length,
				TEST_ATTR_HANDLE, PLDM_BIOS_STRING,
				sizeof(TEST_VALUE_TABLE_CURRENT_STR),
				TEST_VALUE_TABLE_CURRENT_STR);
		if (bios_special_case != VALUE_TABLE_ERROR)
			*table_response = PLDM_SUCCESS;
		break;
	default:
		printf("PLDM_TEST Failed: INvalid Table type");
		return OPAL_PARAMETER;

	}

	/* Add padding data */
	memset(*bios_table + *bios_table_length - sizeof(uint32_t) - pad_len, 0, pad_len);


	checksum = htole32(pldm_crc32(*bios_table, *bios_table_length - sizeof(uint32_t)
				- pad_len));
	memcpy(*bios_table + *bios_table_length - sizeof(uint32_t), (void *)&checksum,
			sizeof(uint32_t));

	return OPAL_SUCCESS;

}


/*
 * This function duplicates BMC functionality for Pldm self test
 * it handle PLDM_REQUEST for PLDM_BIOS and reply with appropriate
 * PLDM_RESPONSE message
 */
int pldm_test_reply_request_bios(void *request_msg, size_t request_len,
		void **response_msg, size_t *response_len)
{
	int rc;
	uint32_t transfer_handle;
	uint8_t transfer_op_flag, table_type;
	uint8_t *bios_table;
	uint32_t bios_table_length = 0;
	size_t payload_length;
	uint8_t pldm_table_response;



	/*
	 * check if command send is PLDM_GET_BIOS_TABLE then only
	 * reply response message and return PLDM_SUCCESS
	 * else return error
	 */
	if (((struct pldm_msg *)request_msg)->hdr.command == PLDM_GET_BIOS_TABLE) {
		payload_length = request_len - sizeof(struct pldm_msg_hdr);
		rc = decode_get_bios_table_req(request_msg, payload_length, &transfer_handle,
				&transfer_op_flag, &table_type);
		if (rc != PLDM_SUCCESS)
			return OPAL_PARAMETER;

		/*  get table entry to reply request on behalf on BMC for PLDM self test */
		rc = get_test_table_entry_bios(table_type, &bios_table,
				&bios_table_length, &pldm_table_response);
		if (rc != OPAL_SUCCESS)
			return rc;

		payload_length = bios_table_length + sizeof(struct pldm_get_bios_table_resp) - 1;

		*response_len = sizeof(struct pldm_msg_hdr)
			+ payload_length - 1;

		*response_msg = malloc(*response_len);
		if (*response_msg == NULL)
			return OPAL_RESOURCE;

		rc = encode_get_bios_table_resp(((struct pldm_msg *)request_msg)->hdr.instance_id,
				pldm_table_response, PLDM_GET_NEXTPART, PLDM_START_AND_END,
				bios_table, payload_length, *response_msg);
		if (rc != PLDM_SUCCESS)
			return OPAL_PARAMETER;

		free(bios_table);
		return OPAL_SUCCESS;
	} else
		return OPAL_PARAMETER;

	return OPAL_SUCCESS;
}


int ast_mctp_message_tx(bool tag_owner __unused, uint8_t msg_tag __unused,
		uint8_t *msg, int len)
{
	int rc;
	uint8_t *pldm_received_msg = msg+1;
	void *response_msg;
	size_t response_len;

	/* TEST Message TYPE: PLDM = 0x01 (000_0001b) as per MCTP - DSP0240 */
	if (msg[0] != 0x01)
		return OPAL_PARAMETER;

	if (((struct pldm_msg *)pldm_received_msg)->hdr.request == PLDM_RESPONSE)
		return OPAL_PARAMETER;

	/* Reply to requests */
	else if (((struct pldm_msg *)pldm_received_msg)->hdr.request == PLDM_REQUEST) {
		switch (((struct pldm_msg *)pldm_received_msg)->hdr.type) {
		case PLDM_OEM:
			rc = pldm_test_reply_request_fileio(pldm_received_msg, len-1,
					&response_msg, &response_len);
			break;
		case PLDM_BIOS:
			rc = pldm_test_reply_request_bios(pldm_received_msg, len-1,
					&response_msg, &response_len);
			break;

		default:
			return OPAL_PARAMETER;
		}

		if (rc != OPAL_SUCCESS)
			return rc;

		if (response_len <= 0)
			return OPAL_PARAMETER;

		pldm_mctp_message_rx(BMC_EID, tag_owner, msg_tag, response_msg, response_len);
		free(response_msg);
	}
	return OPAL_SUCCESS;
}

static int test_write_before_init(void)
{
	size_t rc;
	char buff[TEST_FILE_IO_LENGTH] = TEST_FILE_IO_BUF1;

	/* Attempt to write using pldm file io before init should return error OPAL_PARAMETER */
	rc = pldm_file_io_write_file(TEST_FILE_IO_HANDLE, 0,
			buff, strlen(buff));
	if (rc != OPAL_HARDWARE) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n", __func__, rc, OPAL_PARAMETER);
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}

static int test_read_before_init(void)
{
	size_t rc;
	char buf_read[TEST_FILE_IO_LENGTH];
	uint64_t size = strlen(TEST_FILE_IO_BUF1);

  /*
   * Attempt to read using pldm file io before init
   * should return error OPAL_PARAMETER
   */
	rc = pldm_file_io_read_file(TEST_FILE_IO_HANDLE,
			TEST_FILE_IO_LENGTH, 0, buf_read, size);
	if (rc != OPAL_HARDWARE) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n",
				__func__, rc, OPAL_HARDWARE);
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}

static int test_fileio_init(void)
{
	size_t rc;

	/* Init PLDM File IO */
	rc = pldm_file_io_init();
	if (rc != OPAL_SUCCESS) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n",
				__func__, rc, OPAL_SUCCESS);
		return rc;
	}
	return OPAL_SUCCESS;
}

static int test_write_after_init_normal_case(void)
{
	size_t rc;
	char buff[TEST_FILE_IO_LENGTH] = TEST_FILE_IO_BUF1;

  /*
   * Attempt to  write using pldm file io should
   * return OPAL SUCCESS after init
   */
	rc = pldm_file_io_write_file(TEST_FILE_IO_HANDLE, 0,
			buff, strlen(buff));

	if (rc != OPAL_SUCCESS) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n",
				__func__, rc, OPAL_SUCCESS);
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}

static int test_read_after_init_normal_case(void)
{
	size_t rc;
	char buf_read[TEST_FILE_IO_LENGTH];
	uint64_t size = strlen(TEST_FILE_IO_BUF1);


  /*
   * Attempt to  read: using pldm file io should
   * return OPAL SUCCESS after init
   */
	rc = pldm_file_io_read_file(TEST_FILE_IO_HANDLE,
			TEST_FILE_IO_LENGTH, 0, buf_read, size);
	if (rc != OPAL_SUCCESS) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n",
				__func__, rc, OPAL_SUCCESS);
		return OPAL_PARAMETER;
	}

	/* Test if buffer read same as buffer send */
	if (strncmp(buf_read, TEST_FILE_IO_BUF1, size) != 0) {
		printf("PLDM_TEST: %s failed :: pldm read string mismatch\n", __func__);
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}


static int test_write_zero_byte(void)
{
	size_t rc;
	char buff[TEST_FILE_IO_LENGTH] = TEST_FILE_IO_BUF1;
	int size = 0;

	/* Attempt to  write using pldm file io should return OPAL SUCCESS after init */
	rc = pldm_file_io_write_file(TEST_FILE_IO_HANDLE, 0,
			buff, size);

	if (rc != OPAL_PARAMETER) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n",
				__func__, rc, OPAL_PARAMETER);
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}



static int test_read_zero_byte(void)
{
	size_t rc;
	char buff_read[TEST_FILE_IO_LENGTH] = TEST_FILE_IO_BUF1;
	int size = 0;


	rc = pldm_file_io_read_file(TEST_FILE_IO_HANDLE, TEST_FILE_IO_LENGTH, 0, buff_read, size);
	if (rc != OPAL_PARAMETER) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n",
				__func__, rc, OPAL_PARAMETER);
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}


static int test_read_greater_than_file_length(void)
{
	size_t rc;
	char buf_read[TEST_FILE_IO_LENGTH + 10];
	uint64_t size = TEST_FILE_IO_LENGTH + 1;


	rc = pldm_file_io_read_file(TEST_FILE_IO_HANDLE, TEST_FILE_IO_LENGTH, 0, buf_read, size);
	if (rc != OPAL_PARAMETER) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n",
				__func__, rc, OPAL_PARAMETER);
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;

}


static int test_write_replied_with_error(void)
{
	size_t rc;
	char buff[TEST_FILE_IO_LENGTH] = TEST_FILE_IO_BUF1;
	int size = strlen(TEST_FILE_IO_BUF1);

	special_reply = PLDM_ERROR;

	/* Attempt to  write using pldm file io should return OPAL SUCCESS after init */
	rc = pldm_file_io_write_file(TEST_FILE_IO_HANDLE, 0, buff,
			size);

	if (rc != OPAL_PARAMETER) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n",
				__func__, rc, OPAL_PARAMETER);
		special_reply = 0;
		return OPAL_PARAMETER;
	}


	special_reply = 0;
	return OPAL_SUCCESS;
}


static int test_read_replied_with_error(void)
{
	size_t rc;
	char buf_read[TEST_FILE_IO_LENGTH];
	uint64_t size = strlen(TEST_FILE_IO_BUF1);

	special_reply = PLDM_ERROR;

	rc = pldm_file_io_read_file(TEST_FILE_IO_HANDLE, TEST_FILE_IO_LENGTH, 0, buf_read, size);
	if (rc != OPAL_PARAMETER) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n",
				__func__, rc, OPAL_PARAMETER);
		special_reply = 0;
		return OPAL_PARAMETER;
	}

	special_reply = 0;
	return OPAL_SUCCESS;

}

static int test_find_lid_by_attr_name_before_init(void)
{
	size_t rc;
	char *lid;

	/*
	 * Attempt to call pldm_bios_find_lid_by_attr_name()
	 * before pldm_bios_init() return error OPAL_HARDWARE
	 */
	rc = pldm_bios_find_lid_by_attr_name(TEST_VALID_ATTR_NAME, &lid);
	if (rc  != OPAL_HARDWARE) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n",
				__func__, rc, OPAL_HARDWARE);
		return OPAL_PARAMETER;

	}
	return OPAL_SUCCESS;
}

static int test_init_pldm_bios_error_string_table(void)
{
	size_t rc;

	bios_special_case = STRING_TABLE_ERROR;

	/*
	 * Attempt to call pldm_bios_init()
	 * when string table return PLDM_ERROR
	 * so pldm_bios_int return OPAL_PARAMETER
	 */
	rc = pldm_bios_init();
	if (rc  != OPAL_PARAMETER) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n",
				__func__, rc, OPAL_PARAMETER);
		bios_special_case = NORMAL_CASE;
		return OPAL_PARAMETER;

	}

	bios_special_case = NORMAL_CASE;
	return OPAL_SUCCESS;
}



static int test_init_pldm_bios_error_attr_table(void)
{

	size_t rc;

	bios_special_case = ATTR_TABLE_ERROR;

	/*
	 * Attempt to call pldm_bios_init()
	 * when attribute table return PLDM_ERROR
	 * so pldm_bios_int return OPAL_PARAMETER
	 */
	rc = pldm_bios_init();
	if (rc  != OPAL_PARAMETER) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n",
				__func__, rc, OPAL_PARAMETER);
		bios_special_case = NORMAL_CASE;
		return OPAL_PARAMETER;

	}

	bios_special_case = NORMAL_CASE;
	return OPAL_SUCCESS;
}


static int test_init_pldm_bios_error_value_table(void)
{
	size_t rc;

	bios_special_case = VALUE_TABLE_ERROR;

	/*
	 * Attempt to call pldm_bios_init()
	 * when value table return PLDM_ERROR
	 * so pldm_bios_int return OPAL_PARAMETER
	 */
	rc = pldm_bios_init();
	if (rc  != OPAL_PARAMETER) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n",
				__func__, rc, OPAL_PARAMETER);
		bios_special_case = NORMAL_CASE;
		return OPAL_PARAMETER;

	}

	bios_special_case = NORMAL_CASE;
	return OPAL_SUCCESS;
}


static int test_init_pldm_bios(void)
{
	size_t rc;

	bios_special_case = NORMAL_CASE;
	rc = pldm_bios_init();
	if (rc  != OPAL_SUCCESS) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n",
				__func__, rc, OPAL_PARAMETER);
		return OPAL_PARAMETER;

	}

	return OPAL_SUCCESS;

}


int test_pldm_bios_find_lid_by_invalid_attr_name(void)
{
	size_t rc;
	char *lid;
	char name[] = "Error";
	/*
	 * Attempt to call pldm_bios_find_lid_by_attr_name()
	 * when name argument not present return error OPAL_PARAMETER
	 */
	rc = pldm_bios_find_lid_by_attr_name(name, &lid);
	if (rc  != OPAL_PARAMETER) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n",
				__func__, rc, OPAL_PARAMETER);
		return OPAL_PARAMETER;

	}

	return OPAL_SUCCESS;
}

int test_pldm_lid_files_init(void)
{
	int rc;

	rc = pldm_lid_files_init(&bl);
	if (rc  != OPAL_SUCCESS) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n", __func__, rc, OPAL_SUCCESS);
		return OPAL_PARAMETER;

	}
	return OPAL_SUCCESS;
}

int test_pldm_read_invalid_lid(void)
{
	int rc;
	char buff[100] = {'\0'};

	rc = bl->read(bl, VMM_SIZE_RESERVED_PER_SECTION * 5, buff, 20);
	if (rc  != OPAL_PARAMETER) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n", __func__, rc, OPAL_PARAMETER);
		return OPAL_PARAMETER;

	}
	return OPAL_SUCCESS;
}

int test_pldm_read_valid_lid_size_greter_than_file_size(void)
{
	int rc;
	char buff[100] = {'\0'};

	rc = bl->read(bl, VMM_SIZE_RESERVED_PER_SECTION * 3, buff, 100);
	if (rc  != OPAL_PARAMETER) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n", __func__, rc, OPAL_PARAMETER);
		return OPAL_PARAMETER;

	}
	return OPAL_SUCCESS;
}

int test_pldm_read_valid_lid_size(void)
{
	int rc;
	char buff[100] = {'\0'};
	int size = 20;

	rc = bl->read(bl, VMM_SIZE_RESERVED_PER_SECTION * 3,
			buff, size);
	if (rc  != OPAL_SUCCESS) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n", __func__, rc, OPAL_SUCCESS);
		return OPAL_PARAMETER;

	}

	/* Test if buffer read is correct */
	if (strncmp(buff, TEST_FILE_IO_BUF1, size) != 0) {
		printf("PLDM_TEST: %s failed :: pldm read string mismatch\n", __func__);
		return OPAL_PARAMETER;
	}
	return OPAL_SUCCESS;
}


struct test_case {
	const char *name;
	int (*fn)(void);
};

#define TEST_CASE(x) { #x, x }

struct test_case test_cases[] = {
	TEST_CASE(test_write_before_init),
	TEST_CASE(test_read_before_init),
	TEST_CASE(test_fileio_init),
	TEST_CASE(test_write_after_init_normal_case),
	TEST_CASE(test_read_after_init_normal_case),
	TEST_CASE(test_write_zero_byte),
	TEST_CASE(test_read_zero_byte),
	TEST_CASE(test_read_greater_than_file_length),
	TEST_CASE(test_write_replied_with_error),
	TEST_CASE(test_read_replied_with_error),
	TEST_CASE(test_find_lid_by_attr_name_before_init),
	TEST_CASE(test_init_pldm_bios_error_string_table),
	TEST_CASE(test_init_pldm_bios_error_attr_table),
	TEST_CASE(test_init_pldm_bios_error_value_table),
	TEST_CASE(test_init_pldm_bios),
	TEST_CASE(test_pldm_bios_find_lid_by_invalid_attr_name),
	TEST_CASE(test_pldm_lid_files_init),
	TEST_CASE(test_pldm_read_invalid_lid),
	TEST_CASE(test_pldm_read_valid_lid_size_greter_than_file_size),
	TEST_CASE(test_pldm_read_valid_lid_size),
	{NULL, NULL}
};


int main(void)
{
	struct test_case *tc = &test_cases[0];
	int rc = 0;

	/* Initialize test buffer for represent file with 0 */
	bzero(pldm_file_io_buff, TEST_FILE_IO_LENGTH);
	pldm_requester_init();

	do {
		rc = tc->fn();
		if (rc != OPAL_SUCCESS) {
			printf("PLDM FILEIO TEST :%s FAILED\n", tc->name);
			return -1;
		}
	} while ((++tc)->fn);
	// This is to kill thread running to take requests
	kill_poller();

	return OPAL_SUCCESS;
}

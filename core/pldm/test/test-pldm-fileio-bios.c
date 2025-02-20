// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// Copyright 2024 IBM Corp.


#include "test-pldm-common.c"

#define TEST_FILE_IO_NAME "81e0066b.lid"
#define TEST_FILE_IO_HANDLE 11
#define TEST_FILE_IO_LENGTH 50
#define TEST_FILE_IO_BUF1 "This is Test buffer Open power Foundation"

enum pldm_completion_codes special_reply;


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

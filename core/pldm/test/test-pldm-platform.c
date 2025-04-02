// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// Copyright 2024 IBM Corp.

#include "test-pldm-common.c"

#define STATESENSOR_RECORD_HANDLE 116
#define STATESENSOR_RECORD_HANDLE_1 187

#define EFFECTER1_RECORD_HANDLE 120
#define EFFECTER2_RECORD_HANDLE 160

enum platform_special_case_code  {
	NORMAL_CASE = 0x00,
	PDR_REPLY_ERROR = 0x02,
	PLATFORM_EVENT_ERROR = 0x03,
	VERIFY_SHUTDOWN = 0x04
};

enum platform_special_case_code platform_special_case = NORMAL_CASE;

/*
 * These structure duplicates BMC functionality for Pldm self test
 * It include PDR entry to be send on behalf of BMC
 */
struct pldm_state_sensor_pdr sensor_test_0 = {
	.hdr = {
		.record_handle = STATESENSOR_RECORD_HANDLE
	},
	.terminus_handle = 1,
	.sensor_id = 3,
	.entity_type = PLDM_ENTITY_SLOT,
	.entity_instance = 1,
	.container_id = 4,
	.sensor_init = 0,
	.sensor_auxiliary_names_pdr = false,
	.composite_sensor_count = 1
};
struct state_sensor_possible_states possible_states_sensor_0_test = {
	.state_set_id = 3222,
	.possible_states_size = 1,
	.states = {
		{.byte = 1}
	}

};


/*
 * These structure duplicates BMC functionality for Pldm self test
 * It include PDR entry to be send on behalf of BMC
 */
struct pldm_state_sensor_pdr sensor_test_1 = {
	.hdr = {
		.record_handle = STATESENSOR_RECORD_HANDLE_1
	},
	.terminus_handle = 1,
	.sensor_id = 3,
	.entity_type = PLDM_ENTITY_SYSTEM_CHASSIS,
	.entity_instance = 1,
	.container_id = 1,
	.sensor_init = 0,
	.sensor_auxiliary_names_pdr = false,
	.composite_sensor_count = 1
};
struct state_sensor_possible_states possible_states_sensor_1_test = {
	.state_set_id = 17,
	.possible_states_size = 1,
	.states = {
		{.byte = 1}
	}
};


/*
 * These structure duplicates BMC functionality for Pldm self test
 * It include PDR entry to be send on behalf of BMC
 */
struct pldm_state_effecter_pdr effecter_test_1 = {
	.hdr = {
		.record_handle = EFFECTER1_RECORD_HANDLE
	},
	.terminus_handle = 1,
	.effecter_id = 38,
	.entity_type = PLDM_ENTITY_SYS_FIRMWARE,
	.entity_instance = 1,
	.container_id = 1,
	.effecter_semantic_id = 0,
	.effecter_init = 0,
	.has_description_pdr = 0,
	.composite_effecter_count = 1
};
struct state_effecter_possible_states possible_states_effecter_1_test = {
	.state_set_id = PLDM_STATE_SET_SW_TERMINATION_STATUS,
	.possible_states_size = 1,
	.states = {
		{.byte = PLDM_SW_TERM_GRACEFUL_RESTART_REQUESTED}
	}

};


/*
 * These structure duplicates BMC functionality for Pldm self test
 * It include PDR entry to be send on behalf of BMC
 */
struct pldm_state_effecter_pdr effecter_test_2 = {
	.hdr = {
		.record_handle = EFFECTER2_RECORD_HANDLE
	},
	.terminus_handle = 1,
	.effecter_id = 31,
	.entity_type = PLDM_ENTITY_SYSTEM_CHASSIS,
	.entity_instance = 1,
	.container_id = 1,
	.effecter_semantic_id = 0,
	.effecter_init = 0,
	.has_description_pdr = 0,
	.composite_effecter_count = 1
};
struct state_effecter_possible_states possible_states_effecter_2_test = {
	.state_set_id = PLDM_STATE_SET_SYSTEM_POWER_STATE,
	.possible_states_size = 1,
	.states = {
		{.byte = PLDM_STATE_SET_SYS_POWER_STATE_OFF_SOFT_GRACEFUL}
	}
};


/*
 * This function duplicates BMC functionality for Pldm self test
 * It will handle pldm response message
 * For now we don't have any response
 */
int pldm_test_verify_response(void *response_msg, size_t response_len)
{
	if (response_len > 0 || response_msg != NULL)
		return OPAL_PARAMETER;
	return OPAL_PARAMETER;

}


int encode_test_state_sensor_pdr(
		struct pldm_state_sensor_pdr *sensor_test,
		struct state_sensor_possible_states
			*possible_states_sensor_test,
		uint8_t **pdr, size_t *pdr_size)
{
	size_t possible_states_size = 0;
	int rc;

	/* calculate sizeof whole struct */
	*pdr_size = sizeof(struct pldm_state_sensor_pdr)
		+ sizeof(struct state_sensor_possible_states) - 1;
	*pdr = malloc(*pdr_size);
	if (*pdr == NULL) {
		perror("PLDM_TEST malloc");
		return OPAL_RESOURCE;
	}
	memset(*pdr, 0, *pdr_size);

	memcpy(*pdr, sensor_test, sizeof(struct pldm_state_sensor_pdr));

	/* For PLDM Test consider only 1 possible state */
	possible_states_size = sizeof(struct state_sensor_possible_states)
		+ possible_states_sensor_test->possible_states_size - 1;

	rc = encode_state_sensor_pdr(
			(struct pldm_state_sensor_pdr *)(*pdr),
			*pdr_size,
			possible_states_sensor_test,
			possible_states_size, pdr_size);
	if (rc != PLDM_SUCCESS)
		return rc;
	return OPAL_SUCCESS;
}


int encode_test_state_effector_pdr(
		struct pldm_state_effecter_pdr *effecter_test,
		struct state_effecter_possible_states
		*possible_states_effecter_test,
		uint8_t **pdr, size_t *pdr_size)
{
	size_t possible_states_size = 0;
	int rc;

	/* calculate sizeof whole struct */
	*pdr_size = sizeof(struct pldm_state_effecter_pdr)
		+ sizeof(struct state_effecter_possible_states)	- 1;
	*pdr = malloc(*pdr_size);
	if (*pdr == NULL) {
		perror("PLDM_TEST malloc");
		return OPAL_RESOURCE;
	}

	memcpy(*pdr, effecter_test, sizeof(struct pldm_state_effecter_pdr));

	/* For PLDM Test consider only 1 possible state */
	possible_states_size = sizeof(struct state_effecter_possible_states)
		+ possible_states_effecter_test->possible_states_size - 1;

	rc = encode_state_effecter_pdr(
			(struct pldm_state_effecter_pdr *)(*pdr),
			*pdr_size, possible_states_effecter_test,
			possible_states_size, pdr_size);
	if (rc != PLDM_SUCCESS)
		return rc;
	return OPAL_SUCCESS;
}

/*
 * This function duplicates BMC functionality for Pldm self test
 * This generate pdr entry for self test
 */
int get_test_pdr_entry(uint32_t record_hndl, uint8_t **pdr,
		size_t *pdr_len, uint32_t *next_record_hndl)
{
	int rc;

	if (record_hndl == 0 || record_hndl == sensor_test_0.hdr.record_handle) {
		rc = encode_test_state_sensor_pdr(
				&sensor_test_0,
				&possible_states_sensor_0_test,
				pdr, pdr_len);
		if (rc != PLDM_SUCCESS)
			return rc;
		/*
		 * if record_handle is equal to first record handle or 0
		 * then encode next data transfer handle with 1st record handle
		 */
		*next_record_hndl = sensor_test_1.hdr.record_handle;

	} else if (record_hndl == sensor_test_1.hdr.record_handle) {

		rc = encode_test_state_sensor_pdr(
				&sensor_test_1,
				&possible_states_sensor_1_test,
				pdr, pdr_len);
		if (rc != PLDM_SUCCESS)
			return rc;
		*next_record_hndl = effecter_test_1.hdr.record_handle;

	} else if (record_hndl == effecter_test_1.hdr.record_handle) {

		rc = encode_test_state_effector_pdr(
				&effecter_test_1,
				&possible_states_effecter_1_test,
				pdr, pdr_len);
		if (rc != PLDM_SUCCESS)
			return rc;
		*next_record_hndl = effecter_test_2.hdr.record_handle;


	} else if (record_hndl == effecter_test_2.hdr.record_handle) {
		rc = encode_test_state_effector_pdr(
				&effecter_test_2,
				&possible_states_effecter_2_test,
				pdr, pdr_len);
		if (rc != PLDM_SUCCESS)
			return rc;
		/*
		 * if record_handle is equal to last record handle
		 * the encode next data transfer handle with 0
		 */
		*next_record_hndl = 0;
	} else
		return OPAL_PARAMETER;

	return OPAL_SUCCESS;

}


static int pldm_test_sensor_event_handle(uint8_t *event_data, size_t event_data_length)
{
	int rc;
	uint16_t sensor_id;
	uint8_t sensor_event_class_type;
	size_t event_class_data_offset;
	uint8_t sensor_offset, event_state, previous_event_state;

	rc = decode_sensor_event_data(event_data,
			event_data_length,
			&sensor_id,
			&sensor_event_class_type,
			&event_class_data_offset);
	if (rc != PLDM_SUCCESS)
		return OPAL_PARAMETER;

	rc = decode_state_sensor_data(event_data + event_class_data_offset,
			event_data_length - event_class_data_offset,
			&sensor_offset,
			&event_state,
			&previous_event_state);
	if (rc != PLDM_SUCCESS)
		return OPAL_PARAMETER;

	if (platform_special_case == VERIFY_SHUTDOWN
			&& event_state != PLDM_SW_TERM_GRACEFUL_SHUTDOWN)
		return OPAL_PARAMETER;

	return OPAL_SUCCESS;

}


/*
 * This function duplicates BMC functionality for Pldm self test
 * it handle PLDM_REQUEST for PLDM_PLATFORM and reply with appropriate
 * PLDM_RESPONSE message
 */
int pldm_test_reply_request_platform(void *request_msg, size_t request_len,
		void **response_msg, size_t *response_len)
{
	uint8_t *pdr = NULL;
	size_t pdr_len;
	int rc = 0;
	int  payload_len = 0, completion_code = PLDM_SUCCESS;
	uint32_t transfer_handle;
	uint8_t transfer_opflag;
	uint16_t request_cnt;
	uint16_t record_chg_num;
	uint32_t record_hndl;
	uint8_t format_version, tid, event_class;
	size_t event_data_offset;
	uint32_t next_record_hndl;

	/* check pldm command received and reply with appropriate pldm response message */
	switch (((struct pldm_msg *)request_msg)->hdr.command) {
	case PLDM_GET_PDR:
		payload_len = request_len - sizeof(struct pldm_msg_hdr);
		rc = decode_get_pdr_req(request_msg, payload_len, &record_hndl, &transfer_handle,
				&transfer_opflag, &request_cnt, &record_chg_num);
		if (rc != PLDM_SUCCESS)
			return rc;

		/* Get pdr entry for self test */
		rc = get_test_pdr_entry(record_hndl, &pdr,
				&pdr_len, &next_record_hndl);
		if (rc != OPAL_SUCCESS)
			return rc;

		payload_len = (sizeof(struct pldm_get_pdr_resp) - 1)
			+ pdr_len;
		*response_len = sizeof(struct pldm_msg_hdr)
			+ payload_len;

		*response_msg = malloc(*response_len);
		if (*response_msg == NULL) {
			perror("PLDM_TEST malloc");
			return OPAL_RESOURCE;
		}

		/*
		 * Check if special testcase to reply with
		 * error completion code.
		 */
		if (platform_special_case == PDR_REPLY_ERROR)
			completion_code = PLDM_ERROR;

		rc = encode_get_pdr_resp(
				((struct pldm_msg *)request_msg)->hdr.instance_id,
				completion_code, next_record_hndl,
				PLDM_GET_NEXTPART, PLDM_START_AND_END,
				pdr_len, pdr, 0, *response_msg);
		if (rc != PLDM_SUCCESS)
			return OPAL_PARAMETER;

		free(pdr);
		break;

	case PLDM_PLATFORM_EVENT_MESSAGE:
		payload_len = request_len - sizeof(struct pldm_msg_hdr);
		rc = decode_platform_event_message_req(request_msg, payload_len, &format_version,
				&tid, &event_class, &event_data_offset);
		if (rc != PLDM_SUCCESS)
			return OPAL_PARAMETER;

		/* Test: if tid and event class same as that expected */
		if (tid != HOST_TID)
			return OPAL_PARAMETER;

		switch (event_class) {
		case PLDM_PDR_REPOSITORY_CHG_EVENT:
			/*
			 * Check if special testcase to reply with
			 * error completion code.
			 */
			if (platform_special_case == PLATFORM_EVENT_ERROR)
				completion_code = PLDM_ERROR;
			break;

		case PLDM_SENSOR_EVENT:
			rc = pldm_test_sensor_event_handle(request_msg +
					sizeof(struct pldm_msg_hdr) + event_data_offset,
					payload_len - event_data_offset);
			if (rc != PLDM_SUCCESS)
				return OPAL_PARAMETER;

			break;

		default:
			return OPAL_PARAMETER;
		}
		*response_len = sizeof(struct pldm_msg_hdr) +
			sizeof(struct pldm_platform_event_message_resp);
		*response_msg = malloc(*response_len);
		if (*response_msg == NULL) {
			perror("PLDM_TEST malloc");
			return OPAL_RESOURCE;
		}

		rc = encode_platform_event_message_resp(
				((struct pldm_msg *)request_msg)->hdr.instance_id,
				completion_code, 0, *response_msg);
		if (rc != PLDM_SUCCESS)
			return OPAL_PARAMETER;

		return PLDM_SUCCESS;

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
		rc = pldm_test_reply_request_platform(pldm_received_msg, len-1,
				&response_msg, &response_len);
		if (rc != OPAL_SUCCESS)
			return rc;

		if (response_len <= 0)
			return OPAL_PARAMETER;

		pldm_mctp_message_rx(BMC_EID, tag_owner,
				msg_tag, response_msg,
				response_len);
		free(response_msg);
	}
	return OPAL_SUCCESS;
}

int test_platform_init_pdr_error(void)
{
	int rc;

	platform_special_case = PDR_REPLY_ERROR;
	rc = pldm_platform_init();
	if (rc != OPAL_PARAMETER) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n",
				__func__, rc, OPAL_PARAMETER);
		platform_special_case = NORMAL_CASE;
		return OPAL_PARAMETER;
	}
	platform_special_case = NORMAL_CASE;
	return OPAL_SUCCESS;

}


int test_platform_init_event_error(void)
{
	int rc;

	platform_special_case = PLATFORM_EVENT_ERROR;
	rc = pldm_platform_init();
	if (rc != OPAL_PARAMETER) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n",
				__func__, rc, OPAL_PARAMETER);
		platform_special_case = NORMAL_CASE;
		return OPAL_PARAMETER;
	}
	platform_special_case = NORMAL_CASE;
	return OPAL_SUCCESS;

}


int test_platform_init_success(void)
{
	int rc;

	platform_special_case = NORMAL_CASE;
	rc = pldm_platform_init();
	if (rc != OPAL_SUCCESS) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n",
				__func__, rc, OPAL_SUCCESS);
		return OPAL_PARAMETER;
	}
	return OPAL_SUCCESS;
}



int test_find_pdr_first_record(void)
{
	int rc;
	uint8_t *pdr_data = NULL;
	uint32_t pdr_size, next_record_handle;

	/*
	 * try to find first pdr record send to repo
	 */
	rc = pldm_platform_pdr_find_record(
			STATESENSOR_RECORD_HANDLE,
			&pdr_data, &pdr_size,
			&next_record_handle);
	if (rc != OPAL_SUCCESS) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n",
				__func__, rc, OPAL_SUCCESS);
		return OPAL_PARAMETER;
	}

	if (pdr_data == NULL || pdr_size < 0) {
		printf("PLDM_TEST: %s failed :: pdr_data = %p pdr size = %d\n",
				__func__, pdr_data, pdr_size);
		if (pdr_data)
			free(pdr_data);
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}


int test_find_pdr_existing_record(void)
{
	int rc;
	uint8_t *pdr_data = NULL;
	uint32_t pdr_size, next_record_handle;

	/*
	 * try to find first pdr record send to repo
	 */
	rc = pldm_platform_pdr_find_record(
			EFFECTER1_RECORD_HANDLE,
			&pdr_data, &pdr_size,
			&next_record_handle);
	if (rc != OPAL_SUCCESS) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n",
				__func__, rc, OPAL_SUCCESS);
		return OPAL_PARAMETER;
	}

	if (pdr_data == NULL || pdr_size < 0) {
		printf("PLDM_TEST: %s failed :: pdr_data = %p pdr size = %d\n",
				__func__, pdr_data, pdr_size);
		if (pdr_data)
			free(pdr_data);
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}

int test_find_pdr_non_existing_record(void)
{
	int rc;
	uint8_t *pdr_data = NULL;
	uint32_t pdr_size, next_record_handle;

	rc = pldm_platform_pdr_find_record(
			400,
			&pdr_data, &pdr_size,
			&next_record_handle);
	if (rc != OPAL_PARAMETER) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n",
				__func__, rc, OPAL_PARAMETER);
		return OPAL_PARAMETER;
	}
	return OPAL_SUCCESS;
}

int test_pldm_platform_initiate_shutdown(void)
{
	int rc;

	platform_special_case = VERIFY_SHUTDOWN;
	rc = pldm_platform_initiate_shutdown();
	if (rc != OPAL_SUCCESS) {
		printf("PLDM_TEST: %s failed :: rc = %d exp %d\n",
				__func__, rc, OPAL_SUCCESS);
		platform_special_case = NORMAL_CASE;
		return OPAL_PARAMETER;
	}
	platform_special_case = NORMAL_CASE;
	return OPAL_SUCCESS;

}

struct test_case {
	const char *name;
	int (*fn)(void);
};

#define TEST_CASE(x) { #x, x }

struct test_case test_cases[] = {
	TEST_CASE(test_platform_init_pdr_error),
	TEST_CASE(test_platform_init_event_error),
	TEST_CASE(test_platform_init_success),
	TEST_CASE(test_find_pdr_first_record),
	TEST_CASE(test_find_pdr_existing_record),
	TEST_CASE(test_find_pdr_non_existing_record),
	TEST_CASE(test_pldm_platform_initiate_shutdown),
	{NULL, NULL}
};


int main(void)
{
	struct test_case *tc = &test_cases[0];
	int rc = 0;

	/* Initialize test buffer for represent file with 0 */
	pldm_requester_init();

	do {
		rc = tc->fn();
		if (rc != OPAL_SUCCESS) {
			printf("PLDM PLATFORM TEST :%s FAILED\n", tc->name);
			return -1;
		}
	} while ((++tc)->fn);

	// This is to kill thread running to take requests
	kill_poller();

	return OPAL_SUCCESS;
}

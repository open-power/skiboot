// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2020 IBM Corp. */

#define MBEDTLS_PKCS7_C
#include "secvar_common_test.c"
#include "../backend/edk2-compat.c"
#include "../backend/edk2-compat-process.c"
#include "../secvar_util.c"
#include "../../crypto/pkcs7/pkcs7.c"
#include "./data/PK.h"
#include "./data/noPK.h"
#include "./data/KEK.h"
#include "./data/invalidkek.h"
#include "./data/malformedkek.h"
#include "./data/db.h"
#include "./data/dbsigneddata.h"
#include "./data/OldTSKEK.h"
#include "./data/multipleKEK.h"
#include "./data/multipleDB.h"
#include "./data/multiplePK.h"
#include "./data/dbx.h"
#include "./data/dbxsha512.h"
#include "./data/dbxmalformed.h"

int reset_keystore(struct list_head *bank __unused) { return 0; }
int add_hw_key_hash(struct list_head *bank __unused) { return 0; }
int delete_hw_key_hash(struct list_head *bank __unused) { return 0; }
int verify_hw_key_hash(void) { return 0; }

const char *secvar_test_name = "edk2-compat";

int secvar_set_secure_mode(void) { return 0; };

int run_test()
{
	int rc = -1;
	struct secvar *tmp;
	char empty[64] = {0};

	// Check pre-process creates the empty variables
	ASSERT(0 == list_length(&variable_bank));
	rc = edk2_compat_pre_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(5 == list_length(&variable_bank));
	tmp = find_secvar("TS", 3, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(64 == tmp->data_size);
	ASSERT(!(memcmp(tmp->data, empty, 64)));

	// Add PK to update and .process()
	printf("Add PK");
	tmp = new_secvar("PK", 3, PK_auth, PK_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("PK", 3, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->data_size);
	ASSERT(PK_auth_len > tmp->data_size); // esl should be smaller without auth
	ASSERT(!setup_mode);

	// Add db, should fail with no KEK
	printf("Add db");
	tmp = new_secvar("db", 3, DB_auth, DB_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	printf("rc is %d %04x\n", rc, rc);
	ASSERT(OPAL_SUCCESS != rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("db", 3, &variable_bank);
	ASSERT(NULL != tmp);

	printf("Add KEK");

	// Add valid KEK, .process(), succeeds 
	tmp = new_secvar("KEK", 4, KEK_auth, KEK_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("KEK", 4, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->data_size);

	// Add valid KEK, .process(), timestamp check fails 

	tmp = new_secvar("KEK", 4, OldTS_KEK_auth, OldTS_KEK_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_PERMISSION == rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("KEK", 4, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->data_size);

	// Add db, .process(), should succeed
	printf("Add db again\n");
	tmp = new_secvar("db", 3, DB_auth, DB_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("db", 3, &variable_bank);
	printf("tmp is %s\n", tmp->key);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->data_size);

	// Add db, .process(), should fail because of timestamp 
	printf("Add db again\n");
	tmp = new_secvar("db", 3, DB_auth, DB_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_PERMISSION == rc);

	// Add valid sha256 dbx
	printf("Add sha256 dbx\n");
	tmp = new_secvar("dbx", 4, dbxauth, dbx_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS == rc);

	// Add invalid KEK, .process(), should fail
	printf("Add invalid KEK\n");
	tmp = new_secvar("KEK", 4, InvalidKEK_auth, InvalidKEK_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS != rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("KEK", 4, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->data_size);

	// Add ill formatted KEK, .process(), should fail
	printf("Add invalid KEK\n");
	tmp = new_secvar("KEK", 4, MalformedKEK_auth, MalformedKEK_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS != rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("KEK", 4, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->data_size);

	// Add multiple KEK ESLs, one of them should sign the db 
	printf("Add multiple KEK\n");
	tmp = new_secvar("KEK", 4, multipleKEK_auth, multipleKEK_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("KEK", 4, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->data_size);

	// Add multiple DB ESLs signed with second key of the KEK 
	printf("Add multiple db\n");
	tmp = new_secvar("db", 3, multipleDB_auth, multipleDB_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("db", 3, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 != tmp->data_size);

	// Add db with signeddata PKCS7 format.
	printf("DB with signed data\n");
	tmp = new_secvar("db", 3, dbsigneddata_auth, dbsigneddata_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS == rc);

	// Delete PK. 
	printf("Delete PK\n");
	tmp = new_secvar("PK", 3, noPK_auth, noPK_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS == rc);
	ASSERT(5 == list_length(&variable_bank));
	ASSERT(0 == list_length(&update_bank));
	tmp = find_secvar("PK", 3, &variable_bank);
	ASSERT(NULL != tmp);
	ASSERT(0 == tmp->data_size);
	ASSERT(setup_mode);

	// Add multiple PK. 
	printf("Multiple PK\n");
	tmp = new_secvar("PK", 3, multiplePK_auth, multiplePK_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS != rc);


	printf("Add invalid dbx\n");
	tmp = new_secvar("dbx", 4, wrongdbxauth, wrong_dbx_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS != rc);

	printf("Add sha512 dbx\n");
	tmp = new_secvar("dbx", 4, dbx512, dbx512_auth_len, 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS == rc);

	printf("Add db(cert) as dbx\n");
	tmp = new_secvar("dbx", 4, DB_auth, sizeof(DB_auth), 0);
	ASSERT(0 == edk2_compat_validate(tmp));
	list_add_tail(&update_bank, &tmp->link);
	ASSERT(1 == list_length(&update_bank));

	rc = edk2_compat_process(&variable_bank, &update_bank);
	ASSERT(OPAL_SUCCESS != rc);

	return 0;
}

int main(void)
{
	int rc;

	list_head_init(&variable_bank);
	list_head_init(&update_bank);

	secvar_storage.max_var_size = 4096;

	rc = run_test();

	clear_bank_list(&variable_bank);
	clear_bank_list(&update_bank);

	return rc;
}

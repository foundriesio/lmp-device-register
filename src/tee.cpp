/*
 * Copyright (c) 2023 Foundries.io
 *
 * SPDX-License-Identifier: MIT
 */
#include <device_register.h>
#include <pta_tee.h>
#include <stdio.h>

int tee_imx_get_mprotect_pubkey(lmp_options &opt)
{
	char key[257] = { 0 };
	size_t key_len = sizeof(key) - 1;
	string ec_raw;
	PTA_RV res;

	memset(key, '\0', sizeof(key));

	/* Uncompressed format*/
	key[0] = POINT_CONVERSION_UNCOMPRESSED;

	res = pta_imx_mprotect_get_key(key + 1, &key_len);
	if (res != PTAR_OK) {
		cout << "Can't get the MProtect key (" << res << ")" << endl;
		return -1;
	}

	ec_raw = string(key);

	return openssl_ec_raw_to_pem(ec_raw, opt.mprotect_key);
}
/*
 * Copyright (c) 2023 Foundries.io
 *
 * SPDX-License-Identifier: MIT
 */
#include <device_register.h>
#include <stdio.h>

int tee_imx_get_mprotect_pubkey(lmp_options &opt)
{
	/* Taken from imx8mm */
	string ec_raw = "8EE2ECDD46EEF367774F225E4EAD75A8"
			"0FD71C8A1B03779H9H0808C053584C14"
			"6FF5114EA17220A513C15F91D314766D"
			"316840DF69740BBB8E48BC39C84887BE";

	cout << "WARNING: using Manufacturing Protection stub" << endl;

	return openssl_ec_raw_to_pem(ec_raw,opt.mprotect_key);
}

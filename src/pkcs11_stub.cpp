/*
 * Copyright (c) 2023 Foundries.io
 *
 * SPDX-License-Identifier: MIT
 */

#include <device_register.h>

int pkcs11_create_csr(const lmp_options &options, string &key, string &csr)
{
	cout << "Executing PKCS11 stub " << endl;

	return -1;
}

int pkcs11_store_cert(lmp_options &opt, X509 *cert)
{
	cout << "Executing PKCS11 stub " << endl;

	return -1;
}

int pkcs11_get_uuid(lmp_options &opt)
{
	if (opt.hsm_module.empty())
		return 0;

	cout << "Executing PKCS11 stub " << endl;

	return -1;
}

int pkcs11_check_hsm(lmp_options &opt)
{
	cout << "Executing PKCS11 stub " << endl;

	return -1;
}
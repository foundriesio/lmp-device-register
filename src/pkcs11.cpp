/*
 * Copyright (c) 2023 Foundries.io
 *
 * SPDX-License-Identifier: MIT
 */

#include <device_register.h>
#include <libp11.h>

#define leave \
({ cerr << "Error !"<< endl; \
   cerr << " Commit: " << GIT_COMMIT << endl; \
   cerr << " File: pkcs11.cpp, Func: " << __func__ \
   << " Line: " << __LINE__ << endl; \
   return -1; })

/* HSM default information */
static const struct lmp_hsm {
	string token;
	string tls_lbl;
	string tls_id;
	string crt_lbl;
	unsigned char crt_id;
} hsm_cfg = {
	.token = HSM_TOKEN_STR,
	.tls_lbl = HSM_TLS_STR,
	.tls_id = HSM_TLS_ID_STR,
	.crt_lbl = HSM_CRT_STR,
	.crt_id = HSM_CRT_ID,
};

int pkcs11_get_uuid(lmp_options &opt)
{
	PKCS11_SLOT *slots{nullptr};
	PKCS11_CTX *ctx{nullptr};
	unsigned int nslots = 0;

	if (opt.hsm_module.empty())
		return 0;

	ctx = PKCS11_CTX_new();
	if (!ctx)
		leave;

	if (PKCS11_CTX_load(ctx, opt.hsm_module.c_str()))
		leave;

	if (PKCS11_enumerate_slots(ctx, &slots, &nslots))
		leave;

	/* UUID format is a requirement for HSM modules (mainly OP-TEE) */
	std::regex UUID("("
			"[a-f0-9]{8}-"
			"[a-f0-9]{4}-"
			"[a-f0-9]{4}-"
			"[a-f0-9]{4}-"
			"[a-f0-9]{12}"
			")");
	std::smatch match;

	for (size_t i = 0; i < nslots && opt.uuid.empty(); i++) {
		string slot_info = string(slots[i].description);

		std::regex_search(slot_info, match, UUID);
		if (match.size() > 0)
			opt.uuid = match.str(1);
	}

	PKCS11_release_all_slots(ctx, slots, nslots);
	PKCS11_CTX_unload(ctx);
	PKCS11_CTX_free(ctx);

	return 0;
}

/* Initialize HSM_TOKEN_STR (aktualizr token) */
static int pkcs11_initialize(const lmp_options &opt)
{
	PKCS11_TOKEN *token = NULL;
	PKCS11_SLOT *slots = NULL;
	PKCS11_SLOT *slot = NULL;
	PKCS11_CTX *ctx = NULL;
	unsigned int nslots;
	char label[32] = { };

	memset(label, ' ', 32);

	ctx = PKCS11_CTX_new();

	if (PKCS11_CTX_load(ctx, opt.hsm_module.c_str()))
		leave;

	if (PKCS11_enumerate_slots(ctx, &slots, &nslots))
		leave;

	slot = PKCS11_find_token(ctx, slots, nslots);

	while (slot && slot->token && slot->token->initialized)
		slot = PKCS11_find_next_token(ctx, slots, nslots, slot);

	if (!slot || !slot->token || slot->token->initialized)
		leave;

	/* We have an un-initialized token */
	token = slot->token;

	/* Remove the 'end of string' character from the label */
	memcpy(label, HSM_TOKEN_STR, strlen(HSM_TOKEN_STR));

	if (PKCS11_init_token(token, opt.hsm_so_pin.c_str(),
			      (const char *)label))
		leave;

	if (PKCS11_open_session(slot, 1))
		leave;

	if (PKCS11_login(slot, 1, opt.hsm_so_pin.c_str()))
		leave;

	if (PKCS11_init_pin(token, opt.hsm_pin.c_str()))
		leave;

	if (PKCS11_logout(slot))
		leave;

	PKCS11_release_all_slots(ctx, slots, nslots);
	PKCS11_CTX_unload(ctx);
	PKCS11_CTX_free(ctx);

	cout << "PKCS11 token " << HSM_TOKEN_STR << " initialized" << endl;

	return 0;
}

/* Create an EC keypair in the HSM (not TPM) and generate a CSR */
int pkcs11_create_csr(const lmp_options &opt, string &pkey, string &csr)
{
	PKCS11_SLOT *slots = NULL;
	PKCS11_SLOT *slot = NULL;
	PKCS11_CTX *ctx = NULL;
	PKCS11_KEY *key = NULL;
	EVP_PKEY *prv = NULL;
	EVP_PKEY *pub = NULL;
	unsigned int nslots = 0;
	unsigned int n = 0;
	PKCS11_EC_KGEN ec = {
		.curve = "P-256",
	};
	PKCS11_KGEN_ATTRS attr = {
		.type = EVP_PKEY_EC,
		.token_label = hsm_cfg.token.c_str(),
		.key_label = hsm_cfg.tls_lbl.c_str(),
		.key_id = hsm_cfg.tls_id.c_str(),
	};
	bool init = false;

	if (opt.hsm_module.empty())
		leave;

	attr.kgen.ec = &ec;
again:
	ctx = PKCS11_CTX_new();

	if (PKCS11_CTX_load(ctx, opt.hsm_module.c_str()))
		leave;

	if (PKCS11_enumerate_slots(ctx, &slots, &nslots))
		leave;

	slot = PKCS11_find_token(ctx, slots, nslots);

	while (slot && slot->token->label != hsm_cfg.token)
		slot = PKCS11_find_next_token(ctx, slots, nslots, slot);

	/* The  HSM_TOKEN_STR was not found, initialize it  */
	if (!slot || slot->token->label != hsm_cfg.token) {
		if (!init) {
			PKCS11_release_all_slots(ctx, slots, nslots);
			PKCS11_CTX_unload(ctx);
			PKCS11_CTX_free(ctx);

			if (pkcs11_initialize(opt))
				leave;

			init = true;
			goto again;
		}
		cout << "PKCS11 token not found after initializing" << endl;
		leave;
	} else {
		cout << "PKCS11 token " << HSM_TOKEN_STR << " found" << endl;
	}

	if (PKCS11_open_session(slot, 1))
		leave;

	if (PKCS11_login(slot, 0, opt.hsm_pin.c_str()))
		leave;

	if (PKCS11_generate_key(slot->token, &attr))
		leave;

	if (PKCS11_enumerate_public_keys(slot->token, &key, &n) || !n)
		leave;

	for ( ; !pub && key && n; key++, n--) {
		if (key->label == hsm_cfg.tls_lbl)
			pub = PKCS11_get_public_key(key);
	}

	if (!pub)
		leave;

	if (PKCS11_enumerate_keys(slot->token, &key, &n) || !n)
		leave;

	for ( ; !prv && key && n; key++, n--) {
		if (key->label == hsm_cfg.tls_lbl)
			prv = PKCS11_get_private_key(key);
	}

	if (!prv)
		leave;

	if (PKCS11_logout(slot))
		leave;

	/* Use OpenSSL to generate the request in the csr buffer */
	if (openssl_gen_csr(opt, pub, prv, csr))
		leave;

	pkey = hsm_cfg.tls_id;

	/* Free the keys */
	EVP_PKEY_free(pub);
	EVP_PKEY_free(prv);

	/* Release context */
	PKCS11_release_all_slots(ctx, slots, nslots);
	PKCS11_CTX_unload(ctx);
	PKCS11_CTX_free(ctx);

	return 0;
}

/* Write a PEM cerficate in the PKCS#11 database (secure storage - ie RPMB ) */
int pkcs11_store_cert(lmp_options &opt, X509 *cert)
{
	PKCS11_SLOT *slots = NULL;
	PKCS11_SLOT *slot = NULL;
	PKCS11_CTX *ctx = NULL;
	unsigned int nslots = 0;

	ctx = PKCS11_CTX_new();

	if (PKCS11_CTX_load(ctx, opt.hsm_module.c_str()))
		leave;

	if (PKCS11_enumerate_slots(ctx, &slots, &nslots))
		leave;

	slot = PKCS11_find_token(ctx, slots, nslots);

	while (slot && slot->token->label != hsm_cfg.token)
		slot = PKCS11_find_next_token(ctx, slots, nslots, slot);

	if (!slot || slot->token->label != hsm_cfg.token)
		leave;

	if (PKCS11_open_session(slot, 1))
		leave;

	if (PKCS11_login(slot, 0, opt.hsm_pin.c_str()))
		leave;

	if (PKCS11_store_certificate(slot->token, cert, (char *)HSM_CRT_STR,
				     (unsigned char *)&hsm_cfg.crt_id,
				     sizeof(hsm_cfg.crt_id), NULL))
		leave;

	if (PKCS11_logout(slot))
		leave;

	cout << "Certificate written to PKCS#11 secure storage" << endl;

	PKCS11_release_all_slots(ctx, slots, nslots);
	PKCS11_CTX_unload(ctx);
	PKCS11_CTX_free(ctx);

	return 0;
}

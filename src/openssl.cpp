 /*
 * Copyright (c) 2023 Foundries.io
 *
 * SPDX-License-Identifier: MIT
 */

#include <device_register.h>

static int add_ext(STACK_OF(X509_EXTENSION)*sk, int nid, char *value)
{
	X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);

	X509_EXTENSION_set_critical(ex, 1);
	if (!ex)
		return -1;

	sk_X509_EXTENSION_push(sk, ex);
	return 0;
}

/* Use external keys (not created with OpenSSL) to generate a CSR */
int openssl_gen_csr(const lmp_options &opt, EVP_PKEY *pub, EVP_PKEY *priv,
		    string &csr)
{
	STACK_OF(X509_EXTENSION) *ext = NULL;
	X509_NAME *name = NULL;;
	X509_REQ *req = NULL;
	BUF_MEM *bptr = NULL;
	BIO *bio = NULL;

	bio = BIO_new(BIO_s_mem());
	req = X509_REQ_new();
	name = X509_REQ_get_subject_name(req);

	if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
				       (const unsigned char *)
				       opt.uuid.c_str(), -1, -1, 0) != 1)
		leave;

	if (X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC,
				       (const unsigned char *)
				       opt.factory.c_str(), -1, -1, 0) != 1)
		leave;

	if (opt.production) {
		if (X509_NAME_add_entry_by_txt(name, LN_businessCategory,
					       MBSTRING_ASC,
					       (const unsigned char *)
					       "production", -1, -1, 0) != 1)
			leave;
	}

	ext = X509_REQ_get_extensions(req);
	if (!ext)
		leave;

	if (add_ext(ext, NID_key_usage, (char *)"digitalSignature"))
		leave;

	if (add_ext(ext, NID_ext_key_usage, (char *)"clientAuth"))
		leave;

	if (X509_REQ_add_extensions(req, ext) != 1)
		leave;

	if (X509_REQ_set_pubkey(req, pub) != 1)
		leave;

	X509_REQ_sign(req, priv, EVP_sha256());

	if (PEM_write_bio_X509_REQ(bio, req) != 1)
		leave;

	BIO_write(bio, "\0", 1);
	BIO_get_mem_ptr(bio, &bptr);
	X509_REQ_free(req);

	/* Output */
	csr = bptr->data;

	bptr->data = NULL;
	BIO_free_all(bio);

	return 0;
}

int openssl_create_csr(const lmp_options &options, string &pkey, string &csr)
{
	STACK_OF(X509_EXTENSION) *ext = NULL;
	X509_NAME *name = NULL;
	X509_REQ *req = NULL;
	BUF_MEM *bptr = NULL;
	BIO *bio = NULL;
	OSSL_ENCODER_CTX *ectx = NULL;
	unsigned char *data = NULL;
	EVP_PKEY_CTX *kctx = NULL;
	EVP_PKEY *key = NULL;
	size_t len = 0;

	bio = BIO_new(BIO_s_mem());
	req = X509_REQ_new();
	name = X509_REQ_get_subject_name(req);

	if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
				       (const unsigned char *)
				       options.uuid.c_str(), -1, -1, 0) != 1)
		leave;

	if (X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC,
				       (const unsigned char *)
				       options.factory.c_str(), -1, -1, 0) != 1)
		leave;


	if (options.production) {
		if (X509_NAME_add_entry_by_txt(name, LN_businessCategory,
					       MBSTRING_ASC,
					       (const unsigned char *)
					       "production", -1, -1, 0) != 1)
			leave;
	}

	ext = X509_REQ_get_extensions(req);

	if (add_ext(ext, NID_key_usage, (char *)"digitalSignature"))
		leave;

	if (add_ext(ext, NID_ext_key_usage, (char *)"clientAuth"))
		leave;

	if (X509_REQ_add_extensions(req, ext) != 1)
		leave;

	kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (!kctx)
		leave;

	if (EVP_PKEY_keygen_init(kctx) <= 0)
		leave;

	if (EVP_PKEY_CTX_set_group_name(kctx, "prime256v1") <= 0)
		leave;

	if (EVP_PKEY_keygen(kctx, &key) <= 0)
		leave;

	ectx = OSSL_ENCODER_CTX_new_for_pkey(key, OSSL_KEYMGMT_SELECT_ALL,
					     "PEM", NULL, NULL);
	if (!ectx)
		leave;

	if (OSSL_ENCODER_to_data(ectx, &data, &len) != 1)
		leave;

	OSSL_ENCODER_CTX_free(ectx);

	if (X509_REQ_set_pubkey(req, key) != 1)
		leave;

	if (!X509_REQ_sign(req, key, EVP_sha256()))
		leave;

	if (PEM_write_bio_X509_REQ(bio, req) != 1)
		leave;

	EVP_PKEY_free(key);
	BIO_write(bio, "\0", 1);
	BIO_get_mem_ptr(bio, &bptr);
	X509_REQ_free(req);

	/* Output */
	csr = bptr->data;
	pkey = string(reinterpret_cast<char *>(data));

	memset(data, 0, len);
	bptr->data = NULL;
	BIO_free_all(bio);

	return 0;
}

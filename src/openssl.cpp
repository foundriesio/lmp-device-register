 /*
 * Copyright (c) 2023 Foundries.io
 *
 * SPDX-License-Identifier: MIT
 */
#include <device_register.h>

#define CUSTOM_EXT_MPROTECT_KEY_OID ((const char *)"1.3.6.1.4.1.294.1.00")

#define leave \
({ cerr << "Error !"<< endl; \
   cerr << "  Commit : " << GIT_COMMIT << endl; \
   cerr << "  File: openssl.cpp, Func: " << __func__ \
   << " Line: " << __LINE__ << endl; \
   return -1; })

static int add_ext(STACK_OF(X509_EXTENSION)*sk, int nid, char *value)
{
	X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);

	X509_EXTENSION_set_critical(ex, 1);
	if (!ex)
		return -1;

	sk_X509_EXTENSION_push(sk, ex);
	return 0;
}

static int add_custom_ext(STACK_OF(X509_EXTENSION)*sk, const char *objectid,
			  string data)
{
	if (data.empty())
		return 0;

	ASN1_OBJECT *oid = OBJ_txt2obj(objectid, 1);
	if (!oid)
		return -1;

	ASN1_OCTET_STRING *str = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(str, (const unsigned char *)data.c_str(),
			     (int)data.size());

	X509_EXTENSION *ex = X509_EXTENSION_create_by_OBJ(NULL, oid, 0, str);
	if (!ex)
		return -1;

	sk_X509_EXTENSION_push(sk, ex);

	ASN1_OBJECT_free(oid);
	ASN1_OCTET_STRING_free(str);
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

	if (add_custom_ext(ext, CUSTOM_EXT_MPROTECT_KEY_OID, opt.mprotect_key))
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

int openssl_create_csr(const lmp_options &opt, string &pkey, string &csr)
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

	if (add_ext(ext, NID_key_usage, (char *)"digitalSignature"))
		leave;

	if (add_ext(ext, NID_ext_key_usage, (char *)"clientAuth"))
		leave;

	if (add_custom_ext(ext, CUSTOM_EXT_MPROTECT_KEY_OID, opt.mprotect_key))
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

int openssl_ec_raw_to_pem(string &raw, string &key_pem)
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *key = NULL;
	char *pem = nullptr;

	OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();

	OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
					(char *)SN_X9_62_prime256v1, 0);

	OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
					 raw.c_str(), raw.size());

	OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (ctx == NULL ||
	    params == NULL ||
	    EVP_PKEY_fromdata_init(ctx) <= 0 ||
	    EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params) <= 0)
		leave;

	BIO *pem_bio = BIO_new(BIO_s_mem());
	if (!pem_bio)
		leave;

	if (PEM_write_bio_PUBKEY_ex(pem_bio, key, NULL, NULL) == 0)
		leave;

	int pem_len = BIO_get_mem_data(pem_bio, &pem);
	if (pem_len < 0)
		leave;

	string pem_str(reinterpret_cast<char *>(pem), pem_len);
	key_pem = pem_str;

	/* Clean up */
	EVP_PKEY_free(key);
	EVP_PKEY_CTX_free(ctx);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);

	return 0;
}
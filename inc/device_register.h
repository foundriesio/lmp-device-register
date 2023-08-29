/*
 * Copyright (c) 2023 Foundries.io
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef DEVICE_REGISTER_H
#define DEVICE_REGISTER_H

#include <exception>
#include <fcntl.h>
#include <glib.h>
#include <iostream>
#include <regex>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string>
#include <sstream>
#include <unistd.h>

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/encoder.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/buffer.h>

#include <boost/algorithm/string.hpp>
#include <boost/beast/core/detail/base64.hpp>
#include <boost/filesystem.hpp>
#include <boost/iostreams/device/file_descriptor.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/program_options.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/interprocess/sync/file_lock.hpp>

#define __weak __attribute__((weak))

/* OS definitions in os-release */
#define LMP_OS_STR "/etc/os-release"
#define OS_FACTORY_TAG "LMP_FACTORY_TAG"
#define OS_FACTORY "LMP_FACTORY"

/* Environment Variables */
#define ENV_DEVICE_FACTORY "DEVICE_FACTORY"
#define ENV_PRODUCTION "PRODUCTION"
#define ENV_OAUTH_BASE "OAUTH_BASE"
#define ENV_DEVICE_API "DEVICE_API"

/* HSM defitions */
#define HSM_TOKEN_STR "aktualizr"
#define HSM_TLS_STR "tls"
#define HSM_TLS_ID_STR "01"
#define HSM_CRT_STR "client"
#define HSM_CRT_ID 3
#define HSM_CRT_ID_STR "03"

/* Files */
#define AKLITE_LOCK "/var/lock/aklite.lock"
#define SOTA_DIR "/var/sota"
#define SOTA_PEM "/client.pem"
#define SOTA_SQL "/sql.db"

using boost::property_tree::ptree;
using std::stringstream;
using std::string;
using std::cerr;
using std::cout;
using std::endl;

struct lmp_options {
	string api_token_header;
	string device_group;
	string api_token;
	string factory;
	string hwid;
	string uuid;
	string name;
	string hsm_module;
	string hsm_so_pin;
	string hsm_pin;
	string sota_dir;
	string pacman_tags;
	bool start_daemon;
	bool use_server;
	bool production;
	bool mlock;
	bool vuuid;
	bool force;
#if defined DOCKER_COMPOSE_APP
	string apps;
	string restorable_apps;
#endif
};

typedef std::map<std::string, string> http_headers;

int auth_register_device(http_headers &headers, ptree &device, ptree &resp);
void auth_get_http_headers(lmp_options &opt, http_headers &headers);
int auth_ping_server(void);

int options_parse(int argc, char **argv, lmp_options &options);

int openssl_create_csr(const lmp_options &options, string &key, string &csr);
int openssl_gen_csr(const lmp_options &options, EVP_PKEY *pub, EVP_PKEY *priv,
		    string &csr);

int pkcs11_create_csr(const lmp_options &options, string &key, string &csr);
int pkcs11_store_cert(lmp_options &opt, X509 *cert);
int pkcs11_get_uuid(lmp_options &options);
int pkcs11_check_hsm(lmp_options &opt);
#endif

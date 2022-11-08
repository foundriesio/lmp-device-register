/*
 * Copyright (c) 2018 Open Source Foundries Limited
 * Copyright (c) 2019 Foundries.io
 *
 * SPDX-License-Identifier: MIT
 */

#include <fcntl.h>

#include <curl/curl.h>
#include <glib.h>
#include <sys/stat.h>

#include <iostream>
#include <sstream>
#include <string>
#include <regex>

#include <libp11.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/encoder.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/buffer.h>

#define B_FORMAT_TEXT   0x8000
#define FORMAT_PEM     (5 | B_FORMAT_TEXT)
#define FORMAT_ASN1     4


#include <boost/algorithm/string.hpp>
#include <boost/beast/core/detail/base64.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/interprocess/sync/file_lock.hpp>

namespace po = boost::program_options;
using boost::property_tree::ptree;
using std::cerr;
using std::cout;
using std::endl;
using std::string;
using std::stringstream;

// OpenSSL works with object labels, while aktualizr works with IDs.
static const string hsm_token_label = "aktualizr";
static const unsigned char hsm_tls_key_id = 1;           // TLS key ID on HSM, when used (for sota.toml)
static const unsigned char hsm_client_cert_id = 3;       // Client certificate's ID on HSM, when used (for sota.toml)
static const string hsm_tls_key_label = "tls";       // TLS key label on HSM, when used (for OpenSSL)
static const string hsm_client_cert_label = "client"; // Uptane key label on HSM, when used (for OpenSSL)

static char WHEELS[] = {'|', '/', '-', '\\'};
typedef std::map<std::string, string> http_headers;

struct Options {
	string api_token;
	string api_token_header;
	string device_group;
	string factory;
	string hwid;
	string uuid;
	string name;
	string hsm_module;
	string hsm_so_pin;
	string hsm_pin;
	string sota_config_dir;
	bool start_daemon;
	bool use_ostree_server;
#ifdef AKLITE_TAGS
	string pacman_tags;
#endif
#if defined DOCKER_COMPOSE_APP
	string apps;
	string restorable_apps;
#endif
	bool is_prod;
};

static void _set_factory_option(std::string& factory) {
	const char* device_factory_env_var = std::getenv("DEVICE_FACTORY");
	if (device_factory_env_var != nullptr) {
		cout << "Using the device factory specified via the environment variable: "
				 << device_factory_env_var << endl;
		factory = device_factory_env_var;
	}
	if (factory.empty()) {
		throw std::invalid_argument("Empty value of the device factory parameter");
	}
}

static void _set_prod_option(bool& is_prod) {
#ifdef PRODUCTION
	is_prod = true;
#else
	is_prod = false;
	const char* production_env_var = std::getenv("PRODUCTION");
	if (production_env_var != nullptr) {
		cout << "Enabling production client certificates via the environment variable" << endl;
		is_prod = true;
	}
#endif
}

static bool _get_options(int argc, char **argv, Options &options)
{
	po::options_description desc("lmp-device-register options");
	desc.add_options()
		("help", "print usage")

		("sota-dir,d", po::value<string>(&options.sota_config_dir)->default_value("/var/sota"),
		 "The directory to install to keys and configuration to.")

#ifdef AKLITE_TAGS
#ifdef DEFAULT_TAG
		("tags,t", po::value<string>(&options.pacman_tags)->default_value(DEFAULT_TAG),
		 "Configure " SOTA_CLIENT " to only apply updates from Targets with these tags. Default is " DEFAULT_TAG)
#else
		("tags,t", po::value<string>(&options.pacman_tags),
		 "Configure " SOTA_CLIENT " to only apply updates from Targets with these tags.")
#endif
#endif
#if defined DOCKER_COMPOSE_APP
		("apps,a", po::value<string>(&options.apps),
		"Configure package-manager for this comma separate list of apps.")
		// Restorable Apps are enabled by default, its list == compose_apps or all Target apps
		// --restorable-apps "app-01[,app-02]" : enable Restorable Apps usage, and its list == UNION(compose_apps, app-01[,app-02])
		// `--restorable-apps ""` : disable Restorable Apps usage
		 ("restorable-apps,A", po::value<string>(&options.restorable_apps)->default_value(" "),
		 "Configure package-manager for this comma separate list of Restorable Apps."
		 "If it is not specified, but a system image is preloaded with Restorable Apps then "
		 "the Restorable App list is set to an empty list which means turning restorable App usage ON and"
		 " the resultant list will be equal to the `apps` list."
		 " Restorable App list = UNION(compose-apps, restorable-apps)")
#endif
		("hwid,i", po::value<string>(&options.hwid)->default_value(HARDWARE_ID),
		 "An identifier for the device's hardware type. Default is " HARDWARE_ID)

		("uuid,u", po::value<string>(&options.uuid),
		 "A per-device UUID. If not provided, one will be generated. "
		 "This is associated with the device, e.g. as the CommonName field "
		 "in certificates related to it.")

		("name,n", po::value<string>(&options.name),
		 "The name of the device as it should appear in the dashboard. If not specified, it will use the device's UUID")

		("device-group,g", po::value<string>(&options.device_group),
		 "Assign the device into a device group")

		("api-token,T", po::value<string>(&options.api_token),
		 "Use an API token for authentication. If not specified, oauth2 will be used")

		("api-token-header,H", po::value<string>(&options.api_token_header)->default_value("OSF-TOKEN"),
		 "Specify a HTTP header to be used for authentication. Defaults to \"OSF-TOKEN\".")

		("start-daemon", po::value<bool>(&options.start_daemon)->default_value(true),
		 "Start the " SOTA_CLIENT " systemd service automatically after performing the registration.")

		("use-ostree-server", po::value<bool>(&options.use_ostree_server)->default_value(true),
		 "Use OSTree Proxy server instead of Device Gateway to pull ostree repo from.")

		("hsm-module,m", po::value<string>(&options.hsm_module),
		 "The path to the PKCS#11 .so for the HSM, if using one.")

		("hsm-so-pin,S", po::value<string>(&options.hsm_so_pin),
		 "The PKCS#11 Security Officer PIN to set up on the HSM, if "
		 "using one.")

		("hsm-pin,P", po::value<string>(&options.hsm_pin),
		 "The PKCS#11 PIN to set up on the HSM, if using one.");

	po::options_description all_options("lmp-device-register all options");
	all_options.add(desc);
	all_options.add_options()
		("stream,s", po::value<string>(&options.factory)->default_value(DEVICE_FACTORY),
		 "The update factory to subscribe to: " DEVICE_FACTORY);

	po::variables_map vm;
	try {
		po::store(po::parse_command_line(argc, reinterpret_cast<const char *const *>(argv), all_options), vm);
		if (vm.count("help") != 0u) {
			cout << desc;
			cout << "Git Commit " << GIT_COMMIT << endl;
			return false;
		}
		po::notify(vm);
		_set_factory_option(options.factory);
		_set_prod_option(options.is_prod);
	} catch (const po::error &o) {
		cout << "ERROR: " << o.what() << endl;
		cout << endl << desc << endl;
		return false;
	}
	return true;
}

static size_t _write_sstream(void *buffer, size_t size, size_t nmemb, void *userp)
{
	auto *body = static_cast<stringstream *>(userp);
	body->write(static_cast<const char *>(buffer), size * nmemb);
	return size * nmemb;
}

class Curl {
	private:
	string _url;
	public:
	Curl(const string &url) {
		_url = url;
		curl_global_init(CURL_GLOBAL_DEFAULT);
		curl = curl_easy_init();
		if (curl != nullptr) {
			curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		}
	}
	~Curl() {
		if(curl != nullptr) {
			curl_easy_cleanup(curl);
		}
		curl_global_cleanup();
	}
	void ParseResponse(stringstream &body, ptree &resp) {
		try {
			read_json(body, resp);
		} catch(const boost::property_tree::json_parser::json_parser_error &e) {
			cerr << "Unable to parse response from: " << _url << " Error is:"<< endl;
			cerr << " " <<  e.message() << endl;
			body.seekg(0);
			cerr << "Raw response was: " << body.str() << endl;
		}
	}
	std::tuple<bool, string> PingEndpoint() {
	  curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
	  CURLcode res = curl_easy_perform(curl);
	  if (res != CURLE_OK) {
	    return {false, "Unable to reach the device registration endpoint " + _url + "; err: " + curl_easy_strerror(res)};
	  }
	  gint64 code = 0;
	  CURLcode get_info_res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
	  if (get_info_res != CURLE_OK) {
	    return {false, "Error while checking the device registration endpoint; err: unable to get curl info: " + string(curl_easy_strerror(get_info_res))};
	  }
	  if (code >= 500) {
	    // 401 or 400 is returned under normal circumstances what indicates that the OTA backend is reachable and functional
	    return {false, "The device registration endpoint is not healthy" + _url + "; status code: " + std::to_string(code)};
	  }
	  return {true, ""};
	}
	gint64 Post(const http_headers &headers, const string &data, ptree &resp)
	{
		stringstream body;
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &_write_sstream);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());

		struct curl_slist *chunk = nullptr;
		for (auto item : headers) {
			string header = item.first + ": " + item.second;
			chunk = curl_slist_append(chunk, header.c_str());
		}

		if (chunk != nullptr) {
			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
		}

		CURLcode res = curl_easy_perform(curl);
		if (res != CURLE_OK) {
			cerr << "Unable to post to " << _url << ": " << curl_easy_strerror(res) << endl;
			exit(1);
		}

		if (chunk != nullptr) {
			curl_slist_free_all(chunk);
		}
		gint64 code = 0;
		res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
		if (res != CURLE_OK) {
			cerr << "Unable to get curl info: " << curl_easy_strerror(res) << endl;
			exit(1);
		}
		ParseResponse(body, resp);
		return code;
	}
	private:
	CURL *curl = nullptr;
};

class TempDir {
	public:
	TempDir() {
		path = (boost::filesystem::temp_directory_path() / boost::filesystem::unique_path()).native();
		if (mkdir(path.c_str(), S_IRWXU) == -1) {
			cerr << "Could not create temporary directory at " << path << endl;
			exit(EXIT_FAILURE);
		}
	}
	~TempDir() {
		boost::filesystem::remove_all(path);
	}
	const string &GetPath() {return path;}

	private:
	string path;
};


static string _spawn(const string& cmd_line)
{
	g_autofree GError *error = nullptr;
	g_autofree gchar *stdout_buff = nullptr;
	g_autofree gchar *stderr_buff = nullptr;
	gint status;

	if (g_spawn_command_line_sync(cmd_line.c_str(), &stdout_buff, &stderr_buff, &status, &error) == 0) {
		cerr << "Unable to run: " << cmd_line << endl;
		cerr << "Error is: " << error->message << endl;
		exit(EXIT_FAILURE);
	}
	if (status != 0) {
		cerr << "Unable to run: " << cmd_line << endl;
		cerr << "STDERR is: " << stderr_buff << endl;
		exit(EXIT_FAILURE);
	}
	if (error != nullptr) {
		cerr << "Unable to run: " << cmd_line << endl;
		exit(EXIT_FAILURE);
	}
	return stdout_buff;
}

int add_ext(STACK_OF(X509_EXTENSION) *sk, int nid, char *value) {
	X509_EXTENSION *ex;
	ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
	X509_EXTENSION_set_critical(ex, 1);
  	if (!ex)
    	return 0;
	sk_X509_EXTENSION_push(sk, ex);
	return 1;
}


// There are two flows:
//
// 1. If hsm_module_in is empty or null, file-based keys will be
//    generated and used. Return value is (key_id, csr).
//
// 2. Otherwise, we initialize a token on the PKCS#11 HSM with label
//    aktualizr, generate the keypair there (label tls, ID 01), and
//    extract the public half. Return value is (key_file, csr).
static std::tuple<string, string> _create_cert(const Options &options, const string& uuid)
{
	string pkey;		// Private key data when no HSM used.
	EVP_PKEY *key{nullptr};

	X509_REQ * x509_req{nullptr};
	X509_NAME * x509_name{nullptr};
	STACK_OF(X509_EXTENSION) * extensions;

	BIO * out{nullptr};
	BUF_MEM *bptr{nullptr};

	const char * key_usage_str = "digitalSignature";
	const char * ex_key_usage_str = "clientAuth";

	// Create output BIO
	out = BIO_new(BIO_s_mem());
	// Create CSR
	x509_req = X509_REQ_new();
	x509_name = X509_REQ_get_subject_name(x509_req);

	if (X509_NAME_add_entry_by_txt(x509_name,"CN", MBSTRING_ASC, (const unsigned char*)uuid.c_str(), -1, -1, 0) != 1){
		throw std::runtime_error("Unable to set CN on CSR");
	}

	if (X509_NAME_add_entry_by_txt(x509_name,"OU", MBSTRING_ASC, (const unsigned char*)options.factory.c_str(), -1, -1, 0) != 1) {
		throw std::runtime_error("Unable to set OU on CSR");
	}
	// create extensions
	extensions = X509_REQ_get_extensions(x509_req);

	if (add_ext(extensions, NID_key_usage, strdup(key_usage_str)) != 1) {
		throw std::runtime_error("Unable to set KeyUsage on CSR");
	}
	if (add_ext(extensions, NID_ext_key_usage, strdup(ex_key_usage_str)) != 1) {
		throw std::runtime_error("Unable to set ExKeyUsage on CSR");
	}
	if (X509_REQ_add_extensions(x509_req, extensions) != 1) {
		throw std::runtime_error("Unable to add v3 extensions to CSR");
	}

	if (options.hsm_module.empty()) {
		// Create a file-based key.
		EVP_PKEY_CTX *gctx{nullptr};
		OSSL_ENCODER_CTX *ectx_key{nullptr};
		string curve_name = "prime256v1";
		const char * outformat = "PEM";
		unsigned char * pkey_data{nullptr};
		size_t pkey_data_len;

		gctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
		if (EVP_PKEY_keygen_init(gctx) <= 0) {
			throw std::runtime_error("EC private key initialization failed");
		}
		if (EVP_PKEY_CTX_set_group_name(gctx, curve_name.c_str()) <= 0) {
			throw std::runtime_error("Unable to use prime256v1 curve");
		}
		if (EVP_PKEY_keygen(gctx, &key) <= 0) {
			throw std::runtime_error("Unable to generate prime256v1 key pair");
		}
		ectx_key = OSSL_ENCODER_CTX_new_for_pkey(
						   key, OSSL_KEYMGMT_SELECT_ALL,
						   outformat, NULL, NULL);

		if (OSSL_ENCODER_to_data(ectx_key, &pkey_data, &pkey_data_len) != 1) {
			throw std::runtime_error("Unable to encode EC private key");
		}
		OSSL_ENCODER_CTX_free(ectx_key);
		// Write private key to string
		pkey = string(reinterpret_cast<char*>(pkey_data));

		if (X509_REQ_set_pubkey(x509_req, key) != 1) {
			throw std::runtime_error("Unable to set public key on CSR");
		}

		if (X509_REQ_sign(x509_req, key, EVP_sha256()) == 0) {
			throw std::runtime_error("Unable to sign CSR");
		}

		if (PEM_write_bio_X509_REQ(out, x509_req) != 1) {
			throw std::runtime_error("Unable to write CSR to BIO");
		}

		EVP_PKEY_free(key);

	} else {
		int rv;
		PKCS11_CTX * ctx; // PKCS11 context
		PKCS11_SLOT * slots_;
		PKCS11_SLOT * iterslots;
		unsigned int nslots;
		PKCS11_SLOT * slot{nullptr};
		PKCS11_TOKEN * tok;

		EVP_PKEY *public_key{nullptr};
		EVP_PKEY *private_key{nullptr};

		PKCS11_KEY * p11_keys;
		PKCS11_KEY * p11_public_key{nullptr};
		PKCS11_KEY * p11_private_key{nullptr};
		unsigned int p11_keys_n;

		PKCS11_EC_KGEN ec = {
			.curve = "P-256"
		};
		PKCS11_KGEN_ATTRS eckg =
		{
			.type = EVP_PKEY_EC,
			.token_label = hsm_token_label.c_str(),
			.key_label = hsm_tls_key_label.c_str(),
			.key_id = (char*)&hsm_tls_key_id,
		};
		eckg.kgen.ec = &ec;


		ctx = PKCS11_CTX_new();
		if (PKCS11_CTX_load(ctx, options.hsm_module.c_str()) != 0) {
			PKCS11_CTX_free(ctx);
			throw std::runtime_error("Couldn't load PKCS11 module");
		}
		// Initialize the HSM and create a key in it.
		if (PKCS11_enumerate_slots(ctx, &slots_, &nslots) != 0) {
			// throw some error and exit
			throw std::runtime_error("Couldn't enumerate PKCS11 slots");
		}
		iterslots = slots_;
		for (unsigned int i = 0; i < nslots; i++, iterslots++) {
			if (iterslots != nullptr  && (tok = iterslots->token) != nullptr) {
				if (hsm_token_label == tok->label) {
					slot = iterslots;
					break;
				}
			}
		}

		if ((slot == nullptr) || (slot->token == nullptr)) {

			iterslots = slots_;
			for (unsigned int ii = 0; ii < nslots; ii++, iterslots++) {
				if (iterslots != nullptr && (iterslots->token) != nullptr && ! (iterslots->token->initialized)) {
					slot = iterslots;
					tok = slot->token;
					break;
				}
			}
			cout << "Initializing new token" << endl;
			// slot not yet initialized
			if (PKCS11_init_token(tok, options.hsm_so_pin.c_str(), hsm_token_label.c_str()) != 0) {
				// token not initialized, exit
				throw std::runtime_error("Couldn't initialize PKCS11 token");
			}
			if (PKCS11_open_session(slot, 1) != 0) {
				throw std::runtime_error("Unable to start PKCS11 rw session1");
			}
			if (PKCS11_login(slot, 1, options.hsm_so_pin.c_str()) != 0) {
				throw std::runtime_error("Unable to login to PKCS11 token with SO pin");
			}
			if (PKCS11_init_pin(tok, options.hsm_pin.c_str()) !=0) {
				// failed to initialize pin, exit
				throw std::runtime_error("Couldn't initialize PKCS11 token pin");
			}
			if (PKCS11_logout(slot) != 0) {
				throw std::runtime_error("Unable to logout from PKCS11 token");
			}
		}
		PKCS11_is_logged_in(slot, 1, &rv);
		if (rv == 0) {
			if (PKCS11_open_session(slot, 1) != 0) {
				throw std::runtime_error("Unable to start PKCS11 rw session");
			}
			if (PKCS11_login(slot, 0, options.hsm_pin.c_str()) != 0) {
				throw std::runtime_error("Unable to login to PKCS11 token");
			}
		}
		// Generates RSA:2048. API doesn't allow to generate EC key pairs yet
		if (PKCS11_generate_key(tok, &eckg) !=0) {
			throw std::runtime_error("Couldn't create RSA keys");
		}
		if (PKCS11_logout(slot) != 0) {
			throw std::runtime_error("Unable to logout from PKCS11 token");
		}
		PKCS11_is_logged_in(slot, 0, &rv);
		if (rv == 0) {
			if (PKCS11_open_session(slot, 0) != 0) {
				throw std::runtime_error("Couldn't open PKCS11 ro session");
			}
			if (PKCS11_login(slot, 0, options.hsm_pin.c_str()) != 0) {
				throw std::runtime_error("Couldn't log into PKCS11 (ro)");
			}
		}
		if (PKCS11_enumerate_public_keys(slot->token, &p11_keys, &p11_keys_n) != 0) {
			throw std::runtime_error("Unable to enumerate PKCS11 public keys");
		}
		for (unsigned int j = 0; j < p11_keys_n; j++, p11_keys++) {
			if (p11_keys != NULL && p11_keys->label != NULL && p11_keys->label == hsm_tls_key_label) {
				p11_public_key = p11_keys;
				break;
			}
		}
		public_key = PKCS11_get_public_key(p11_public_key);
		if (X509_REQ_set_pubkey(x509_req, public_key) != 1) {
			throw std::runtime_error("Unable to set public key on CSR");
		}
		if (PKCS11_enumerate_keys(slot->token, &p11_keys, &p11_keys_n) != 0) {
			throw std::runtime_error("Unable to enumerate PKCS11 public keys");
		}
		for (unsigned int k = 0; k < p11_keys_n; k++, p11_keys++) {
			if (p11_keys != NULL && p11_keys->label != NULL && p11_keys->label == hsm_tls_key_label) {
				p11_private_key = p11_keys;
				break;
			}
		}
		private_key = PKCS11_get_private_key(p11_private_key);

		X509_REQ_sign(x509_req, private_key, EVP_sha256());    // returns 0 in case of HSM

		if (PEM_write_bio_X509_REQ(out, x509_req) != 1) {
			throw std::runtime_error("Unable to write CSR to BIO");
		}
		if (PKCS11_logout(slot) != 0) {
			throw std::runtime_error("Unable to logout from PKCS11 token");
		}

		EVP_PKEY_free(public_key);
		EVP_PKEY_free(private_key);

		if (ctx != nullptr) {
			PKCS11_release_all_slots(ctx, slots_, nslots);
			PKCS11_CTX_unload(ctx);
			PKCS11_CTX_free(ctx);
		}
		pkey = string(reinterpret_cast<const char*>(&hsm_tls_key_id));
	}
	// terminate the char * with null to avoid garbage in the string representation
	BIO_write(out, "\0", 1);
	BIO_get_mem_ptr(out, &bptr);
	string csr(bptr->data);
	bptr->data = NULL;

	X509_REQ_free(x509_req);
	BIO_free_all(out);

	return std::make_tuple(pkey, csr);
}

static string _get_oauth_token(const string &factory, const string &device_uuid)
{
	ptree json;
	string data;
	std::map<string, string> headers;
	string url;
	if (getenv("OAUTH_BASE") != nullptr) {
		url = getenv("OAUTH_BASE");
	} else {
		url = "https://app.foundries.io/oauth";
	}

	data = "client_id=" + device_uuid;
	cout << "Using " << data << endl;
	data += "&scope=" + factory + ":devices:create";

	gint64 code = Curl(url + "/authorization/device/").Post(headers, data, json);
	if (code != 200) {
		cerr << "Unable to create device authorization request: HTTP_" << code << endl;
		exit(EXIT_FAILURE);
	}

	cout << endl;
	cout << "----------------------------------------------------------------------------" << endl;
	cout << "Visit the link below in your browser to authorize this new device. This link" << endl;
	cout << "will expire in " << (json.get<int>("expires_in") / 60) << " minutes." << endl;
	cout << "  Device Name: " << device_uuid << endl;
	cout << "  User code: " << json.get<string>("user_code") << endl;
	cout << "  Browser URL: " << json.get<string>("verification_uri") << endl;
	cout << endl;

	data = "grant_type=urn:ietf:params:oauth:grant-type:device_code";
	data += "&device_code=" + json.get<string>("device_code");
	data += "&client_id=" + device_uuid;
	data += "&scope=" + factory + ":devices:create";

	string msg;
	int i=0, interval = json.get<int>("interval");

	while (true) {
		gint64 code = Curl(url + "/token/").Post(headers, data, json);
		if(code == 200) {
			return json.get<string>("access_token");
		} else if (code == 400) {
			if (json.get<string>("error") == "authorization_pending") {
				cout << "Waiting for authorization ";
				cout << WHEELS[i++ % sizeof(WHEELS)] << "\r" << std::flush;
				sleep(interval);
			} else {
				cerr << "Error authorizing device: ";
				cerr << json.get<string>("error_description") << endl;
				exit(EXIT_FAILURE);
			}
		}
		else {
			cout << "HTTP(" << code << ") error. Pausing for 2 seconds" << endl;
			sleep(2);
		}
	}
}

static void _assert_permissions(const string &sota_config_dir)
{
	string test_file = sota_config_dir + "/.test";
	int fd = open(test_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		cerr << "Unable to write to " << sota_config_dir << ". Please run as root" << endl;
		exit(EXIT_FAILURE);
	}
	close(fd);
	unlink(test_file.c_str());
}

static void _assert_not_registered(const string &sota_config_dir)
{
	string path = sota_config_dir + "/sql.db";
	if (access(path.c_str(), F_OK ) == 0 ) {
		cerr << "ERROR: Device appears to already be registered in " << path << endl;
		exit(EXIT_FAILURE);
	}
}

static void _assert_not_running() {
	const char* const lock_path{"/var/lock/aklite.lock"};
	if (!boost::filesystem::exists(lock_path)) {
		return;
	}
	boost::interprocess::file_lock lock{lock_path};
	try {
		if (!lock.try_lock_sharable()) {
			cerr << "ERROR: " SOTA_CLIENT " daemon appears to be running" << endl;
			exit(EXIT_FAILURE);
		}
	} catch (...) {
		cerr << "ERROR: failed to check whether " SOTA_CLIENT " is running" << endl;
		exit(EXIT_FAILURE);
	}
}

static bool ends_with(const std::string &s, const std::string &suffix)
{
	string::size_type ssz = s.size(), sufsz = suffix.size();
	return ssz >= sufsz && s.compare(ssz - sufsz, sufsz, suffix) == 0;
}

static string get_device_id(const Options& options) {
	string uuid; // resultant device ID, must be in UUID format
	PKCS11_CTX * ctx; // PKCS11 context
	PKCS11_SLOT * slots_;
	unsigned int nslots;
	PKCS11_SLOT * slot{nullptr};
	// Ensure a UUID is available.
	if (!options.uuid.empty()) {
		uuid = options.uuid;
	} else if (!options.hsm_module.empty()) {
		// Fetch from PKCS11 if available as part of the slot information
		ctx = PKCS11_CTX_new();
		if (PKCS11_CTX_load(ctx, options.hsm_module.c_str()) != 0) {
			PKCS11_CTX_free(ctx);
			throw std::runtime_error("Couldn't load PKCS11 module");
		}
		// Initialize the HSM and create a key in it.
		if (PKCS11_enumerate_slots(ctx, &slots_, &nslots) != 0) {
			throw std::runtime_error("Couldn't enumerate PKCS11 slots");
		}
		slot = slots_;
		if (nslots > 1) {
			slot = &slots_[0];
		}
		if (slot == nullptr) {
			throw std::runtime_error("Slot not found");
		}
		// Assume all slots have the same description (UUID)
		uuid = slot->description;

		if (ctx != nullptr) {
			PKCS11_release_all_slots(ctx, slots_, nslots);
			PKCS11_CTX_unload(ctx);
			PKCS11_CTX_free(ctx);
		}
	}
	// If ID is not specified as a command line param and cannot be fecthed from PKCS11 (slot uuid)
	// then just use boost uuid generator (why not use it by default ???)
	if (uuid.empty()) {
		boost::uuids::uuid tmp = boost::uuids::random_generator()();
		uuid = boost::uuids::to_string(tmp);
	}
	return uuid;
}

int main(int argc, char **argv)
{
	Options options;
	if (!_get_options(argc, argv, options)) {
		return EXIT_FAILURE;
	}

	if (!options.hsm_module.empty()) {
		if (options.hsm_so_pin.empty() || options.hsm_pin.empty()) {
			cerr << "--hsm-module given without both --hsm-so-pin and --hsm-pin" << endl;
			return EXIT_FAILURE;
		}
	} else if (!options.hsm_so_pin.empty() || !options.hsm_pin.empty()) {
		cerr << "--hsm-module missing but --hsm-so-pin and/or --hsm-pin given" << endl;
		return EXIT_FAILURE;
	}

	_assert_permissions(options.sota_config_dir);
	_assert_not_registered(options.sota_config_dir);
	_assert_not_running();

	const string final_uuid{get_device_id(options)};

	http_headers headers{
	    {"Content-type", "application/json"}
	}; // headers of a request to the device registration endpoint DEVICE_API (by default https://api.foundries.io/ota/devices/)
	if (options.api_token.empty()) {
	  // if a token is not specified as a command line parameter then try to get an oauth token
	  // from the Foundries' auth endpoint (https://app.foundries.io/oauth/authorization/device/)
	  cout << "Token is not specified, getting an oauth token from Foundries' auth endpoint..." << endl;
	  string token = _get_oauth_token(options.factory, final_uuid);
	  string token_base64;
	  token_base64.resize(boost::beast::detail::base64::encoded_size(token.size()));
	  boost::beast::detail::base64::encode(&token_base64[0], token.data(), token.size());

	  headers["Authorization"] = "Bearer " + token_base64;
	} else {
	  headers[options.api_token_header] = options.api_token;
	}

	const char* device_api = std::getenv("DEVICE_API");
	if (device_api != nullptr) {
	  cout << "Using DEVICE_API: " << device_api << endl;
	} else {
	  device_api = DEVICE_API;
	}

	// check if the device registration server and endpoint are reachable before creating a device key&CSR and posting request to the backend.
	const auto ping_res{Curl(device_api).PingEndpoint()};
	if (!std::get<0>(ping_res)) {
	  cerr << std::get<1>(ping_res) << endl;
	  exit(EXIT_FAILURE);
	}

	string pkey, csr;
	std::tie(pkey, csr) = _create_cert(options, final_uuid);
	if (options.name.empty()) {
		options.name = final_uuid;
	}
	cout << "Registering device, " << options.name << ", to factory " << options.factory << "." << endl;
	if (options.uuid.empty()) {
		cout << "Device UUID: " << final_uuid << endl;
	}

	ptree device;
	device.put("name", options.name);
	device.put("uuid", final_uuid);
	device.put("csr", csr);
	device.put("hardware-id", options.hwid);
	device.put("sota-config-dir", options.sota_config_dir);
	device.put<bool>("use-ostree-server", options.use_ostree_server);
	if (!options.hsm_module.empty()) {
		device.put("overrides.tls.pkey_source", "\"pkcs11\"");
		device.put("overrides.tls.cert_source", "\"pkcs11\"");
		device.put("overrides.storage.tls_pkey_path", "");
		device.put("overrides.storage.tls_clientcert_path", "");
		device.put("overrides.import.tls_pkey_path", "");
		device.put("overrides.import.tls_clientcert_path", "");
	}
#ifdef AKLITE_TAGS
	if (!options.pacman_tags.empty()) {
		device.put("overrides.pacman.tags", "\"" + options.pacman_tags + "\"");
	}
#endif
#ifdef DOCKER_COMPOSE_APP
	string apps_root = options.sota_config_dir + "/compose-apps";
	device.put("overrides.pacman.type", "\"ostree+compose_apps\"");
	device.put("overrides.pacman.compose_apps_root", "\"" + apps_root + "\"");
	if (!options.apps.empty()) {
		device.put("overrides.pacman.compose_apps", "\"" + options.apps + "\"");
	}
	string reset_apps_root = options.sota_config_dir + "/reset-apps";
	device.put("overrides.pacman.reset_apps_root", "\"" + reset_apps_root + "\"");

	if (!options.restorable_apps.empty()) {
		device.put("overrides.pacman.reset_apps", "\"" + options.restorable_apps + "\"");
	} else if (boost::filesystem::exists(reset_apps_root)) {
		// if `restorable-apps` is not specified but a system image is preloaded with Restorable Apps then force restorable-apps ON
		cout << "Device is preloaded with Restorable Apps, turning their usage ON" << endl;
		device.put("overrides.pacman.reset_apps", "\"\"");
	}
#endif
	if (!options.device_group.empty()) {
		device.put("group", options.device_group);
	}
	stringstream data;
	write_json(data, device);

	ptree resp;
	gint64 code = Curl(device_api).Post(headers, data.str(), resp);
	if (code != 201) {
		cerr << "Unable to create device: HTTP_" << code << endl;
		if (resp.data().length() != 0) {
			cerr << resp.data() << endl;
		}
		for (auto it: resp) {
			cerr << it.first << ": " << it.second.data() << endl;
		}
		exit(EXIT_FAILURE);
	}
	if (options.hsm_module.empty()) {
		// If the private key is meant to be a file, put it in the right place.
		std::ofstream out(options.sota_config_dir + "/pkey.pem");
		out << pkey;
		out.close();
	}
	for (auto it: resp) {
		string name = options.sota_config_dir + "/" + it.first;
		std::ofstream out(name);

		out << it.second.data();

		if (!options.hsm_module.empty() && ends_with(name, ".toml")) {
			// We additionally write the entire p11 section. (We can't tell the server
			// the PIN, and don't want to parse/modify TOML to add it, so just write
			// the whole thing.)
			out << endl;
			out << "[p11]" << endl;
			out << "module = \"" << options.hsm_module << "\"" << endl;
			out << "pass = \"" << options.hsm_pin << "\"" << endl;
			out << "label = \"" << hsm_token_label << "\"" << endl;
			out << "tls_pkey_id = \"" << std::setfill('0') << std::setw(2) << +hsm_tls_key_id << "\"" << endl;
			out << "tls_clientcert_id = \"" << std::setfill('0') << std::setw(2) << +hsm_client_cert_id << "\"" << endl;
			out << endl;
		}

		out.close();

		if (!options.hsm_module.empty() && ends_with(name, ".pem")) {
			// The client cert is now saved on disk, but  needs to be stored in
			// the HSM. The copy we leave in sota_config_dir is just a "courtesy".
			PKCS11_CTX * ctx; // PKCS11 context
			PKCS11_SLOT * slots_;
			unsigned int nslots;
			PKCS11_SLOT * slot{nullptr};
			PKCS11_TOKEN * tok;
			X509* cert{nullptr};
			FILE * cert_fp ;
			char * cert_label{nullptr};
			int rv;

			cert_fp = fopen(name.c_str(), "rb");
			if (!cert_fp) {
				throw std::runtime_error("Could not open certificate file");
			}
			cert = PEM_read_X509(cert_fp, NULL, 0, NULL);
			if (!cert) {
				throw std::runtime_error("Could not read certificate file");
			}

			if (cert_fp) {
				fclose(cert_fp);
			}

			ctx = PKCS11_CTX_new();
			if (PKCS11_CTX_load(ctx, options.hsm_module.c_str()) != 0) {
				PKCS11_CTX_free(ctx);
				throw std::runtime_error("Couldn't load PKCS11 module");
			}
			// Initialize the HSM and create a key in it.
			if (PKCS11_enumerate_slots(ctx, &slots_, &nslots) != 0) {
				// throw some error and exit
				throw std::runtime_error("Couldn't enumerate PKCS11 slots");
			}
			for (unsigned int i = 0; i < nslots; i++, slots_++) {
				if (slots_ != nullptr  && (tok = slots_->token) != nullptr) {
					if (hsm_token_label == tok->label) {
						slot = slots_;
						break;
					}
				}
			}
			if ((slot == nullptr) || (slot->token == nullptr)) {
				throw std::runtime_error("PKCS11 token not initilized");
			}
			PKCS11_is_logged_in(slot, 1, &rv);
			if (rv == 0) {
				if (PKCS11_open_session(slot, 1) != 0) {
					throw std::runtime_error("Unable to start PKCS11 rw session");
				}
				if (PKCS11_login(slot, 0, options.hsm_pin.c_str()) != 0) {
					throw std::runtime_error("Unable to login to PKCS11 token");
				}
			}

			cert_label = strdup(hsm_client_cert_label.c_str());
			cout << "Preparing to store cert from " << name << " to pkcs11 token with label " << slot->token->label << endl;
			if (PKCS11_store_certificate(slot->token,
				     cert,
				     cert_label,
				     (unsigned char *)&hsm_client_cert_id,
				     sizeof(hsm_client_cert_id),
				     NULL) != 0) {
				throw std::runtime_error("Could not store certificate");
			}
			if (PKCS11_logout(slot) != 0) {
				throw std::runtime_error("Unable to logout from PKCS11 token");
			}
			if (ctx != nullptr) {
				PKCS11_release_all_slots(ctx, slots_, nslots);
				PKCS11_CTX_unload(ctx);
				PKCS11_CTX_free(ctx);
			}
		}
	}
	cout << "Device is now registered." << endl;

	if (options.start_daemon) {
		cout << "Starting " SOTA_CLIENT " daemon" << endl;
		_spawn("systemctl start " SOTA_CLIENT);
	}

	return EXIT_SUCCESS;
}

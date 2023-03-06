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
static const string hsm_tls_key_id = "01";           // TLS key ID on HSM, when used (for sota.toml)
static const string hsm_client_cert_id = "03";       // Client certificate's ID on HSM, when used (for sota.toml)
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

static string _pkcs11_tool(const string &module, const string &cmd)
{
	return _spawn("pkcs11-tool --module " + module + " " + cmd);
}

static string _pkcs11_tool(const string &module, const string &cmd, const string &pin)
{
	return _pkcs11_tool(module, "--pin " + pin + " " + cmd);
}

static void _setenv(const char *name, const char *value)
{
	int rc = setenv(name, value, 1);

	if (rc != 0) {
		cerr << "failed to set " << name << ": " << strerror(errno) << endl;
		exit(EXIT_FAILURE);
	}
}

static void _unsetenv(const char *name)
{
	int rc = unsetenv(name);

	if (rc != 0) {
		cerr << "failed to set " << name << ": " << strerror(errno) << endl;
		exit(EXIT_FAILURE);
	}
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
	TempDir tmp_dir;
	string pkey;		// Private key data when no HSM used.
	string pkey_file;	// Temporary file for private key when no HSM is used.

	// Create the key.
	if (options.hsm_module.empty()) {
		// Create a file-based key.
		pkey = _spawn("openssl ecparam -genkey -name prime256v1");
		pkey_file = tmp_dir.GetPath() + "/pkey.pem";
		std::ofstream pkey_out(pkey_file);
		pkey_out << pkey << endl;
		pkey_out.close();
	}
	// Create a CSR.
	string csr = tmp_dir.GetPath() + "/device.csr";
	string cnf = tmp_dir.GetPath() + "/device.cnf";
	std::ofstream cnf_out(cnf);
	if (!options.hsm_module.empty()) {
		cnf_out << "openssl_conf = openssl_init" << endl;
		cnf_out << endl;
		cnf_out << "[openssl_init]" << endl;
		cnf_out << "providers = provider_sect" << endl;
		cnf_out << endl;
		cnf_out << "[provider_sect]" << endl;
		cnf_out << "default = default_sect" << endl;
		cnf_out << "pkcs11 = pkcs11_sect" << endl;
		cnf_out << endl;
		cnf_out << "[default_sect]" << endl;
		cnf_out << "activate = 0" << endl;
		cnf_out << "[pkcs11_sect]" << endl;
		cnf_out << "module = /usr/lib/ossl-modules/pkcs11.so" << endl;
		cnf_out << "pkcs11-module-path = " << options.hsm_module << endl;
		cnf_out << "activate = 0" << endl;
		cnf_out << endl;
	}
	cnf_out << "[req]" << endl;
	cnf_out << "prompt = no" << endl;
	cnf_out << "distinguished_name = dn" << endl;
	cnf_out << "req_extensions = ext" << endl;
	cnf_out << "default_md = sha256" << endl;
	cnf_out << endl;
	cnf_out << "[dn]" << endl;
	cnf_out << "CN=" << uuid << endl;
	cnf_out << "OU=" << options.factory << endl;
	if (options.is_prod) {
		cnf_out << "businessCategory=production" << endl;
	}
	cnf_out << endl;
	cnf_out << "[ext]" << endl;
	cnf_out << "keyUsage=critical, digitalSignature" << endl;
	cnf_out << "extendedKeyUsage=critical, clientAuth" << endl;
	cnf_out.close();

	if (options.hsm_module.empty()) {
		csr = _spawn("openssl req -new -config " + cnf + " -key " + pkey_file);
		return std::make_tuple(pkey, csr);
	} else {
		// Initialize the HSM and create a key in it.
		_setenv("OPENSSL_CONF", cnf.c_str());

		/* Just in case we are using a TPM */
		_setenv("TPM2_PKCS11_STORE", "/var/tpm2_pkcs11");

		/* Remove the database, we dont care if it fails */
		g_spawn_command_line_sync("rm /var/tpm2_pkcs11/tpm2_pkcs11.sqlite3",
					  NULL, NULL, NULL, NULL);

		/* Create the keys */
		_pkcs11_tool(options.hsm_module,
			     "--init-token --label " + hsm_token_label +
			     " --so-pin " + options.hsm_so_pin);
		_pkcs11_tool(options.hsm_module,
			     "--init-pin --token-label " + hsm_token_label +
			     " --so-pin " + options.hsm_so_pin +
			     " --pin " + options.hsm_pin);
		_pkcs11_tool(options.hsm_module,
			     "--keypairgen --key-type EC:prime256v1"
			     " --token-label " + hsm_token_label +
			     " --id " + hsm_tls_key_id +
			     " --label " + hsm_tls_key_label,
			     options.hsm_pin);

		/* Generate the certificate */
		string key = "\"pkcs11:token=" + hsm_token_label +
			";object=" + hsm_tls_key_label +
			";type=private" +
			";pin-value=" + options.hsm_pin + "\"";

		csr = _spawn("openssl req -new -key " + key);
		_unsetenv("OPENSSL_CONF");
		return std::make_tuple(hsm_tls_key_id, csr);
	}
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
	const string db_path{sota_config_dir + "/sql.db"};
	const string cert_path{sota_config_dir + "/client.pem"};
	if (access(db_path.c_str(), F_OK) == 0 && access(cert_path.c_str(), F_OK) == 0) {
		cerr << "ERROR: Device appears to already be registered in " <<  sota_config_dir << endl;
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
  // Ensure a UUID is available.
  if (!options.uuid.empty()) {
    uuid = options.uuid;
  } else if (!options.hsm_module.empty()) {
    // Fetch from PKCS11 if available as part of the slot information
    string slot_info = _pkcs11_tool(options.hsm_module, "--list-slots");
    std::regex re("(Slot .*: )([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})");
    std::smatch match;
    std::regex_search(slot_info, match, re);
    if (match.size() > 2) {
      uuid = match.str(2);
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
			const auto resp_elem{it.first};
			if (resp_elem == "errors") {
				cerr << resp_elem << ":" << endl;
				for (auto it_err: it.second) {
					cerr << '\t' << it_err.first << ": " << it_err.second.data() << endl;
				}
			} else {
				cerr << it.first << ": " << it.second.data() << endl;
			}
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
			out << "tls_pkey_id = \"" << hsm_tls_key_id << "\"" << endl;
			out << "tls_clientcert_id = \"" << hsm_client_cert_id << "\"" << endl;
			out << endl;
		}

		out.close();

		if (!options.hsm_module.empty() && ends_with(name, ".pem")) {
			// The client cert is now saved on disk, but  needs to be stored in
			// the HSM. The copy we leave in sota_config_dir is just a "courtesy".
			TempDir tmp_dir;
			string client_der = tmp_dir.GetPath() + "/client.der";
			_spawn("openssl x509 -inform pem -in " + name + string(" -out ").append(client_der));
			_pkcs11_tool(options.hsm_module, "-w " + client_der + string(" -y cert --id ").append(hsm_client_cert_id), options.hsm_pin);
		}
	}
	cout << "Device is now registered." << endl;

	if (options.start_daemon) {
		cout << "Starting " SOTA_CLIENT " daemon" << endl;
		_spawn("systemctl start " SOTA_CLIENT);
	}

	return EXIT_SUCCESS;
}

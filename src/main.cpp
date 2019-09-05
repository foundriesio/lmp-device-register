/*
 * Copyright (c) 2018 Open Source Foundries Limited
 * Copyright (c) 2019 Foundries.io
 *
 * SPDX-License-Identifier: MIT
 */

#include <fcntl.h>

#include <curl/curl.h>
#include <ostree-1/ostree.h>

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

static bool _validate_stream(const std::vector<string>& streams, const string& stream)
{
	return std::find(streams.begin(), streams.end(), stream) != streams.end();
}

static bool _get_options(int argc, char **argv, string &stream, string &hwid, string &uuid, string &name, string &hsm_module, string &hsm_so_pin, string &hsm_pin, string &sota_config_dir)
{
	std::vector<std::string> streams;
	boost::split(streams, DEVICE_STREAMS, [](char c){return c == ',';});

	po::options_description desc("lmp-device-register options");
	desc.add_options()
		("help", "print usage")

		("sota-dir,d", po::value<string>(&sota_config_dir)->default_value("/var/sota"),
		 "The directory to install to keys and configuration to.")

		("stream,s", po::value<string>(&stream)->default_value(streams[0]),
		 "The update stream to subscribe to: " DEVICE_STREAMS)

		("hwid,i", po::value<string>(&hwid),
		 "An identifier for the device's hardware type. If not provided, "
		 "the current OSTree SHA in the TUF repo will be used to determine "
		 "a value.")

		("uuid,u", po::value<string>(&uuid),
		 "A per-device UUID. If not provided, one will be generated. "
		 "This is associated with the device, e.g. as the CommonName field "
		 "in certificates related to it.")

		("name,n", po::value<string>(&name)->required(),
		 "The name of the device as it should appear in the dashboard.")

		("hsm-module,m", po::value<string>(&hsm_module),
		 "The path to the PKCS#11 .so for the HSM, if using one.")

		("hsm-so-pin,S", po::value<string>(&hsm_so_pin),
		 "The PKCS#11 Security Officer PIN to set up on the HSM, if "
		 "using one.")

		("hsm-pin,P", po::value<string>(&hsm_pin),
		 "The PKCS#11 PIN to set up on the HSM, if using one.");
	po::variables_map vm;

	try {
		po::store(po::parse_command_line(argc, reinterpret_cast<const char *const *>(argv), desc), vm);
		if (vm.count("help") != 0u) {
			cout << desc;
			return false;
		}
		po::notify(vm);
		if (vm.count("stream") && !_validate_stream(streams, stream)) {
			throw po::validation_error(po::validation_error::invalid_option_value, "--stream", stream);
		}
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
		if (curl)
			curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	}
	~Curl() {
		if(curl)
			curl_easy_cleanup(curl);
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
	long GetJson(ptree &resp)
	{
		stringstream body;
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &_write_sstream);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);

		curl_easy_perform(curl);
		long code;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

		ParseResponse(body, resp);
		return code;
	}
	long Post(const http_headers &headers, const string &data, ptree &resp)
	{
		stringstream body;
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &_write_sstream);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());

		struct curl_slist *chunk = NULL;
		for (auto item : headers) {
			string header = item.first + ": " + item.second;
			chunk = curl_slist_append(chunk, header.c_str());
		}

		if (chunk)
			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

		curl_easy_perform(curl);

		if (chunk)
			curl_slist_free_all(chunk);
		long code;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
		ParseResponse(body, resp);
		return code;
	}
	private:
	CURL *curl = nullptr;
};

static string _get_ostree_hash()
{
	g_autofree GError *error = nullptr;
	g_autoptr(OstreeSysroot) sysroot = ostree_sysroot_new(nullptr);

	if (!ostree_sysroot_load(sysroot, nullptr, &error)) {
		cerr << "Unable to find OSTree repo: " << error->message << endl;
		exit(EXIT_FAILURE);
	}

	return ostree_deployment_get_csum(
		ostree_sysroot_get_booted_deployment(sysroot));
}

static string _get_hwid(const string &stream)
{
	ptree resp;
	const string hash = _get_ostree_hash();
	string url = "https://api.foundries.io/lmp/repo/" + stream + "/api/v1/user_repo/targets.json";
	long status = Curl(url).GetJson(resp);
	if (status != 200) {
		cerr << "Unable to get " << url << ": HTTP_" << status << endl;
		exit(EXIT_FAILURE);
	}
	for (ptree::value_type &target : resp.get_child("signed.targets")) {
		if (hash == target.second.get_child("hashes").get<string>("sha256")) {
			return target.second.get_child("custom.hardwareIds").front().second.get_value<string>();
		}
	}

	cerr << "Unable to find this ostree image(" << hash << ") in the TUF targets list: ";
	cerr << url  << endl;
	exit(EXIT_FAILURE);
}

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

	if (!g_spawn_command_line_sync(cmd_line.c_str(), &stdout_buff, &stderr_buff, &status, &error)) {
		cerr << "Unable to run: " << cmd_line << endl;
		cerr << "Error is: " << error->message << endl;
		exit(EXIT_FAILURE);
	}
	if (status) {
		cerr << "Unable to run: " << cmd_line << endl;
		cerr << "STDERR is: " << stderr_buff << endl;
		exit(EXIT_FAILURE);
	}
	if (error) {
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
//    generated and used. Return value is (device_uuid, key_id,
//    csr).
//
// 2. Otherwise, we initialize a token on the PKCS#11 HSM with label
//    aktualizr, generate the keypair there (label tls, ID 01), and
//    extract the public half. Return value is (device_uuid, key_file,
//    csr).
static std::tuple<string, string, string> _create_cert(const string &stream, const string &device_uuid, const string &hsm_module, const string &hsm_so_pin, const string &hsm_pin)
{
	TempDir tmp_dir;
	string pkey;		// Private key data when no HSM used.
	string pkey_file;	// Temporary file for private key when no HSM is used.
	string uuid;

	// Create the key.
	if (hsm_module.empty()) {
		// Create a file-based key.
		pkey = _spawn("openssl ecparam -genkey -name prime256v1");
		pkey_file = tmp_dir.GetPath() + "/pkey.pem";
		std::ofstream pkey_out(pkey_file);
		pkey_out << pkey << endl;
		pkey_out.close();
	} else {
		// Initialize the HSM and create a key in it.
		_pkcs11_tool(hsm_module,
			     "--init-token --label " + hsm_token_label +
			     " --so-pin " + hsm_so_pin);
		_pkcs11_tool(hsm_module,
			     "--init-pin --token-label " + hsm_token_label +
			     " --so-pin " + hsm_so_pin +
			     " --pin " + hsm_pin);
		_pkcs11_tool(hsm_module,
			     "--keypairgen --key-type EC:prime256v1"
			     " --token-label " + hsm_token_label +
			     " --id " + hsm_tls_key_id +
			     " --label " + hsm_tls_key_label,
			     hsm_pin);
	}

	// Ensure a UUID is available.
	if (!device_uuid.empty()) {
		uuid = device_uuid;
	} else if (!hsm_module.empty()) {
		// Fetch from PKCS11 if available as part of the slot information
		string slot_info = _pkcs11_tool(hsm_module, "--list-slots");
		std::regex re("(Slot .*: )([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})");
		std::smatch match;
		std::regex_search(slot_info, match, re);
		if (match.size() > 2) {
			uuid = match.str(2);
		}
	}
	// If UUID not available, generate one
	if (uuid.empty()) {
		boost::uuids::uuid tmp = boost::uuids::random_generator()();
		uuid = boost::uuids::to_string(tmp);
	}

	// Create a CSR.
	string csr = tmp_dir.GetPath() + "/device.csr";
	string cnf = tmp_dir.GetPath() + "/device.cnf";
	std::ofstream cnf_out(cnf);
	if (!hsm_module.empty()) {
		cnf_out << "openssl_conf = oc" << endl;
		cnf_out << endl;
		cnf_out << "[oc]" << endl;
		cnf_out << "engines = eng" << endl;
		cnf_out << endl;
		cnf_out << "[eng]" << endl;
		cnf_out << "pkcs11 = p11" << endl;
		cnf_out << endl;
		cnf_out << "[p11]" << endl;
		cnf_out << "engine_id = pkcs11" << endl;
		cnf_out << "dynamic_path = /usr/lib/engines-1.1/pkcs11.so" << endl;
		cnf_out << "MODULE_PATH = " << hsm_module << endl;
		cnf_out << "PIN = " << hsm_pin << endl;
		cnf_out << "init = 0" << endl;
		cnf_out << endl;
	}
	cnf_out << "[req]" << endl;
	cnf_out << "prompt = no" << endl;
	cnf_out << "distinguished_name = dn" << endl;
	cnf_out << "req_extensions = ext" << endl;
	cnf_out << endl;
	cnf_out << "[dn]" << endl;
	cnf_out << "CN=" << uuid << endl;
	cnf_out << "OU=" << stream << endl;
	cnf_out << endl;
	cnf_out << "[ext]" << endl;
	cnf_out << "keyUsage=critical, digitalSignature" << endl;
	cnf_out << "extendedKeyUsage=critical, clientAuth" << endl;
	cnf_out.close();

	if (hsm_module.empty()) {
		csr = _spawn("openssl req -new -config " + cnf + " -key " + pkey_file);
		return std::make_tuple(uuid, pkey, csr);
	} else {
		string key = "\"pkcs11:token=" + hsm_token_label +
			";object=" + hsm_tls_key_label +
			";type=private" +
			";pin-value=" + hsm_pin + "\"";
		// For some stupid reason, using OPENSSL_CONF in the
		// environment works fine here, while using openssl
		// req -new -config doesn't work with engines.
		_setenv("OPENSSL_CONF", cnf.c_str());
		csr = _spawn("openssl req -new -engine pkcs11 -keyform engine -key " + key);
		_unsetenv("OPENSSL_CONF");
		return std::make_tuple(uuid, hsm_tls_key_id, csr);
	}
}

static string _get_oauth_token(const string &device_uuid)
{
	ptree json;
	string data = "client_id=" + device_uuid;
	std::map<string, string> headers;
	string url;
	if (getenv("OAUTH_BASE"))
		url = getenv("OAUTH_BASE");
	else
		url = "https://app.foundries.io/oauth";

	long code = Curl(url + "/authorization/device/").Post(headers, data, json);
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

	string msg;
	int i=0, interval = json.get<int>("interval");

	while (true) {
		long code = Curl(url + "/token/").Post(headers, data, json);
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

static bool ends_with(const std::string &s, const std::string &suffix)
{
	string::size_type ssz = s.size(), sufsz = suffix.size();
	return ssz >= sufsz && s.compare(ssz - sufsz, sufsz, suffix) == 0;
}

int main(int argc, char **argv)
{
	string stream, hwid, uuid, name, hsm_module, hsm_so_pin, hsm_pin, sota_config_dir;
	if (!_get_options(argc, argv, stream, hwid, uuid, name, hsm_module, hsm_so_pin, hsm_pin, sota_config_dir))
		return EXIT_FAILURE;

	cout << "Registering device, " << name << ", to stream " << stream << "." << endl;
	if (hwid.length() == 0) {
		hwid = _get_hwid(stream);
		cout << "Probed hardware ID: " << hwid << endl;
	}
	if (!hsm_module.empty()) {
		if (hsm_so_pin.empty() || hsm_pin.empty()) {
			cerr << "--hsm-module given without both --hsm-so-pin and --hsm-pin" << endl;
			return EXIT_FAILURE;
		}
	} else if (!hsm_so_pin.empty() || !hsm_pin.empty()) {
		cerr << "--hsm-module missing but --hsm-so-pin and/or --hsm-pin given" << endl;
		return EXIT_FAILURE;
	}

	_assert_permissions(sota_config_dir);

	string final_uuid, pkey, csr;
	std::tie(final_uuid, pkey, csr) = _create_cert(stream, uuid, hsm_module, hsm_so_pin, hsm_pin);
	if (uuid.empty()) {
		cout << "Device UUID: " << final_uuid << endl;
	}

	string token = _get_oauth_token(final_uuid);
	string token_base64;
	token_base64.resize(boost::beast::detail::base64::encoded_size(token.size()));
	boost::beast::detail::base64::encode(&token_base64[0], token.data(), token.size());

	http_headers headers;
	headers["Content-type"] = "application/json";
	headers["Authorization"] = "Bearer " + token_base64;

	ptree device;
	device.put("name", name);
	device.put("uuid", final_uuid);
	device.put("csr", csr);
	device.put("hardware-id", hwid);
	device.put("sota-config-dir", sota_config_dir);
	if (!hsm_module.empty()) {
		device.put("overrides.tls.pkey_source", "\"pkcs11\"");
		device.put("overrides.tls.cert_source", "\"pkcs11\"");
		device.put("overrides.storage.tls_pkey_path", "");
		device.put("overrides.storage.tls_clientcert_path", "");
		device.put("overrides.import.tls_pkey_path", "");
		device.put("overrides.import.tls_clientcert_path", "");
	}
	stringstream data;
	write_json(data, device);

	ptree resp;
	long code = Curl(DEVICE_API).Post(headers, data.str(), resp);
	if (code != 201) {
		cerr << "Unable to create device: HTTP_" << code << endl;
		if (resp.data().length()) {
			cerr << resp.data() << endl;
		}
		for (auto it: resp) {
			cerr << it.first << ": " << it.second.data() << endl;
		}
		exit(EXIT_FAILURE);
	}
	if (hsm_module.empty()) {
		// If the private key is meant to be a file, put it in the right place.
		std::ofstream out(sota_config_dir + "/pkey.pem");
		out << pkey;
		out.close();
	}
	for (auto it: resp) {
		string name = sota_config_dir + "/" + it.first;
		std::ofstream out(name);

		out << it.second.data();

		if (!hsm_module.empty() && ends_with(name, ".toml")) {
			// We additionally write the entire p11 section. (We can't tell the server
			// the PIN, and don't want to parse/modify TOML to add it, so just write
			// the whole thing.)
			out << endl;
			out << "[p11]" << endl;
			out << "module = \"" << hsm_module << "\"" << endl;
			out << "pass = \"" << hsm_pin << "\"" << endl;
			out << "tls_pkey_id = \"" << hsm_tls_key_id << "\"" << endl;
			out << "tls_clientcert_id = \"" << hsm_client_cert_id << "\"" << endl;
			out << endl;
		}

		out.close();

		if (!hsm_module.empty() && ends_with(name, ".pem")) {
			// The client cert is now saved on disk, but  needs to be stored in
			// the HSM. The copy we leave in sota_config_dir is just a "courtesy".
			TempDir tmp_dir;
			string client_der = tmp_dir.GetPath() + "/client.der";
			_spawn("openssl x509 -inform pem -in " + name + " -out " + client_der);
			_pkcs11_tool(hsm_module, "-w " + client_der + " -y cert --id " + hsm_client_cert_id, hsm_pin);
		}
	}
	cout << "Device is now registered." << endl;

	return EXIT_SUCCESS;
}

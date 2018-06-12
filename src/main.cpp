#include <fcntl.h>

#include <curl/curl.h>
#include <ostree-1/ostree.h>

#include <iostream>
#include <sstream>
#include <string>

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

static char WHEELS[] = {'|', '/', '-', '\\'};
typedef std::map<std::string, string> http_headers;

static bool _get_options(int argc, char **argv, string &stream, string &hwid, string &name)
{
	po::options_description desc("lmp-device-register options");
	desc.add_options()
		("help", "print usage")

		("hwid,i", po::value<string>(&hwid),
		 "The hardware-id of the device. If not provided the script will look for"
		 "the current ostree sha in the tufrepo and find the hardware-id frm that.")

		("stream,s", po::value<string>(&stream)->default_value("release"),
		 "The update stream to subscribe to: release, postmerge, premerge.")

		("name,n", po::value<string>(&name)->required(),
		 "The name of the device as it should appear in the dashboard.");
	po::variables_map vm;

	try {
		po::store(po::parse_command_line(argc, reinterpret_cast<const char *const *>(argv), desc), vm);
		if (vm.count("help") != 0u) {
			cout << desc;
			return false;
		}
		po::notify(vm);
		if (vm.count("stream") && stream != "release" && stream != "premerge" && stream != "postmerge") {
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
	public:
	Curl(const string &url) {
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
	long GetJson(ptree &resp)
	{
		stringstream body;
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &_write_sstream);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);

		curl_easy_perform(curl);
		long code;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

		read_json(body, resp);
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
		read_json(body, resp);

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
	gint status;

	if(!g_spawn_command_line_sync(cmd_line.c_str(), &stdout_buff, NULL, &status, &error)) {
		cerr << "Unable to run: " << cmd_line << endl;
		cerr << "Error is: " << error->message << endl;
		exit(EXIT_FAILURE);
	}
	if(error) {
		cerr << "Unable to run: " << cmd_line << endl;
		cerr << "STDERR is: " << stderr << endl;
		exit(EXIT_FAILURE);
	}
	return stdout_buff;
}


static std::tuple<string, string, string> _create_cert(const string &stream)
{
	TempDir tmp_dir;
	string pkey = _spawn("openssl ecparam -genkey -name prime256v1");

	// Create the private key
	string pkey_file = tmp_dir.GetPath() + "/pkey.pem";
	std::ofstream pkey_out(pkey_file);
	pkey_out << pkey << endl;
	pkey_out.close();

	//Make key signing request
	boost::uuids::uuid tmp = boost::uuids::random_generator()();
	const string device_uuid = boost::uuids::to_string(tmp);

	string csr = tmp_dir.GetPath() + "/device.csr";
	string cnf = tmp_dir.GetPath() + "/device.cnf";
	std::ofstream cnf_out(cnf);
	cnf_out << "[req]" << endl;
	cnf_out << "prompt = no" << endl;
	cnf_out << "distinguished_name = dn" << endl;
	cnf_out << "req_extensions = ext" << endl;
	cnf_out << endl;
	cnf_out << "[dn]" << endl;
	cnf_out << "CN=" << device_uuid << endl;
	cnf_out << "OU=" << stream << endl;
	cnf_out << endl;
	cnf_out << "[ext]" << endl;
	cnf_out << "keyUsage=critical, digitalSignature" << endl;
	cnf_out << "extendedKeyUsage=critical, clientAuth";
	cnf_out.close();

	csr = _spawn("openssl req -new -config " + cnf + " -key " + pkey_file);
	return std::make_tuple(device_uuid, pkey, csr);
}

static string _get_oauth_token(const string &device_uuid)
{
	ptree json;
	string data = "client_id=" + device_uuid;
	std::map<string, string> headers;

	long code = Curl("https://foundries.io/oauth/authorization/device/").Post(headers, data, json);
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
		long code = Curl("https://foundries.io/oauth/token/").Post(headers, data, json);
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

static void _assert_permissions()
{
	const char *test_file = "/var/sota/.test";
	int fd = open(test_file, O_WRONLY | O_CREAT  | O_TRUNC);
	if (fd < 0) {
		cerr << "Unable to write to /var/sota. Please run as root" << endl;
		exit(EXIT_FAILURE);
	}
	close(fd);
	unlink(test_file);

}

int main(int argc, char **argv)
{
	string stream, hwid, name;
	if (!_get_options(argc, argv, stream, hwid, name))
		return EXIT_FAILURE;

	cout << "Registering device, " << name << ", to stream " << stream << "." << endl;
	if (hwid.length() == 0) {
		hwid = _get_hwid(stream);
		cout << "Probed hardware ID as " << hwid << endl;
	}

	_assert_permissions();

	string device_uuid, pkey, csr;
	std::tie(device_uuid, pkey, csr) = _create_cert(stream);
	string token = _get_oauth_token(device_uuid);

	http_headers headers;
	headers["Content-type"] = "application/json";
	headers["Authorization"] = "Bearer " + boost::beast::detail::base64_encode(token);

	ptree device;
	device.put("name", name);
	device.put("uuid", device_uuid);
	device.put("csr", csr);
	device.put("hardware-id", hwid);
	stringstream data;
	write_json(data, device);

	ptree resp;
	long code = Curl("https://api.foundries.io/lmp/devices/").Post(headers, data.str(), resp);
	if (code != 201) {
		cerr << "Unable to create device: HTTP_" << code << endl;
		exit(EXIT_FAILURE);
	}
	std::ofstream out("/var/sota/pkey.pem");
	out << pkey;
	out.close();
	for (auto it: resp) {
		std::ofstream out("/var/sota/" + it.first);
		out << it.second.data();
		out.close();
	}
	cout << "Device is now registered." << endl;

	return EXIT_SUCCESS;
}

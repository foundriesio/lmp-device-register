#include <curl/curl.h>
#include <ostree-1/ostree.h>

#include <iostream>
#include <sstream>
#include <string>

#include <boost/program_options.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

namespace po = boost::program_options;
using boost::property_tree::ptree;
using std::cerr;
using std::cout;
using std::endl;
using std::string;
using std::stringstream;


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

	cerr << "Unable to find this ostree image in the TUF targets list." << endl;
	exit(EXIT_FAILURE);
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

	return EXIT_SUCCESS;
}

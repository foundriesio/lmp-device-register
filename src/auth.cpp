/*
 * Copyright (c) 2023 Foundries.io
 *
 * SPDX-License-Identifier: MIT
 */

#include <device_register.h>
#include <curl.hpp>

namespace b64 = boost::beast::detail::base64;
using boost::property_tree::ptree;

static void dump_resp_error(string message, gint64 code, ptree resp)
{
	cerr << message << ": HTTP_" << code << endl;
	if (resp.data().length())
		cerr << resp.data() << endl;

	for (const auto& it: resp) {
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
}

/* Returns the access_token on success, and empty string on errors */
static string get_oauth_token(const string &factory, const string &device_uuid)
{
	const char *env = getenv(ENV_OAUTH_BASE);
	char WHEELS[] = { '|', '/', '-', '\\' };
	std::map<string, string> headers;
	string data;
	string url;
	ptree json;

	url = env == nullptr ? OAUTH_API : env;

	data = "client_id=" + device_uuid;
	data += "&scope=" + factory + ":devices:create";

	gint64 code = Curl(url + "/authorization/device/").Post(headers, data, json);
	if (code != 200) {
		dump_resp_error("Unable to create device authorization request", code, json);
		return "";
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
	int i = 0;
	int interval = json.get<int>("interval");

	while (true) {
		gint64 code = Curl(url + "/token/").Post(headers, data, json);

		if (code == 200)
			return json.get<string>("access_token");

		if (code != 400) {
			cout << "HTTP(" << code << ") error..." << endl;
			sleep(2);
			continue;
		}

		/* Process */
		if (json.get<string>("error") == "authorization_pending") {
			cout << "Waiting for authorization ";
			cout << WHEELS[i++ % sizeof(WHEELS)] << "\r" << std::flush;
			sleep(interval);
		} else {
			dump_resp_error("Error authorizing device", code, json);
			return "";
		}
	}
}

/*
 * Headers of a request to the device registration endpoint DEVICE_API
 * Default https://api.foundries.io/ota/devices/
 */
int auth_get_http_headers(lmp_options &opt, http_headers &headers)
{
	if (!opt.api_token.empty()) {
		headers[opt.api_token_header] = opt.api_token;
		return 0;
	}

	/*
	 * If a token is not specified as a command line parameter then try
	 * to get an oauth token from the Foundries' auth endpoint
	 * https://app.foundries.io/oauth/authorization/device/
	 */
	cout << "Foundries providing auth token " << endl;
	string token = get_oauth_token(opt.factory, opt.uuid);
	if (token.empty())
		return -1;
	string token_base64;

	token_base64.resize(b64::encoded_size(token.size()));
	b64::encode(&token_base64[0], token.data(), token.size());

	headers["Authorization"] = "Bearer " + token_base64;
	return 0;
}

/* Register device using the oauth token. Token need "devices:create" scope */
int auth_register_device(http_headers &headers, ptree &device, ptree &resp)
{
	const char *api = std::getenv(ENV_DEVICE_API);
	stringstream data;
	gint64 code;

	if (api == nullptr)
		api = DEVICE_API;

	write_json(data, device);
	code = Curl(api).Post(headers, data.str(), resp);
	if (code != 201) {
		dump_resp_error("Unable to create device", code, resp);
		return -1;
	}

	return 0;
}

int auth_ping_server(void)
{
	/* Get the device API from the environment */
	const char *api = std::getenv(ENV_DEVICE_API);
	if (api == nullptr)
		api = DEVICE_API;

	cout << "Using DEVICE_API: " << api << endl;
	const auto ping_res{Curl(api).PingEndpoint()};

	if (!std::get<0>(ping_res)) {
		cerr << std::get<1>(ping_res) << endl;
		return -1;
	}

	return 0;
}

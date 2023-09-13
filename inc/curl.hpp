/*
 * Copyright (c) 2023 Foundries.io
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CURL_H
#define CURL_H

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

#include <curl/curl.h>

using boost::property_tree::ptree;
using std::stringstream;
using std::string;
using std::cerr;
using std::cout;
using std::endl;

static size_t write_sstream(void *buf, size_t size, size_t nmemb, void *userp)
{
	auto *body = static_cast<stringstream *>(userp);

	body->write(static_cast<const char *>(buf), size * nmemb);

	return size * nmemb;
}

class Curl {
private:
	string _url;
public:
	Curl(const string &url)
	{
		_url = url;
		curl_global_init(CURL_GLOBAL_DEFAULT);
		curl = curl_easy_init();
		if (curl != nullptr) {
			curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		}
	}
	~Curl()
	{
		if (curl != nullptr) {
			curl_easy_cleanup(curl);
		}
		curl_global_cleanup();
	}
	void ParseResponse(stringstream &body, ptree &resp)
	{
		try {
			read_json(body, resp);
		} catch (const boost::property_tree::json_parser::json_parser_error &e) {
			cerr << "Unable to parse response from: " << _url << " Error is:" << endl;
			cerr << " " <<  e.message() << endl;
			body.seekg(0);
			cerr << "Raw response was: " << body.str() << endl;
		}
	}
	std::tuple<bool, string> PingEndpoint()
	{
		curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
		CURLcode res = curl_easy_perform(curl);
		if (res != CURLE_OK) {
			return { false,
				"Unable to reach the device registration endpoint " + _url + "; err: " + curl_easy_strerror(res) };
		}
		gint64 code = 0;
		CURLcode get_info_res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
		if (get_info_res != CURLE_OK) {
			return { false,
				"Error while checking the device registration endpoint; err: unable to get curl info: " + string(curl_easy_strerror(get_info_res)) };
		}
		if (code >= 500) {
			// 401 or 400 is returned under normal circumstances what indicates that the OTA backend is reachable and functional
			return { false,
				"The device registration endpoint is not healthy" + _url + "; status code: " + std::to_string(code) };
		}
		return { true, "" };
	}
	gint64 Post(const http_headers &headers, const string &data, ptree &resp)
	{
		stringstream body;
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &write_sstream);
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
			return -1;
		}

		if (chunk != nullptr) {
			curl_slist_free_all(chunk);
		}

		gint64 code = 0;
		res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
		if (res != CURLE_OK) {
			cerr << "Unable to get curl info: " << curl_easy_strerror(res) << endl;
			return -1;
		}
		ParseResponse(body, resp);
		return code;
	}
private:
	CURL *curl = nullptr;
};

#endif

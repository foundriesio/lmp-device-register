/*
 * Copyright (c) 2023 Foundries.io
 *
 * SPDX-License-Identifier: MIT
 */
#include "device_register.h"

using boost::property_tree::ptree;

namespace po = boost::program_options;

#define OPT_DEF_STR(str, option, def, help) \
(str, po::value<string>(&option)->default_value(def), help)

#define OPT_DEF_BOOL(str, option, def, help) \
(str, po::value<bool>(&option)->default_value(def), help)

#define OPT_STR(str, option, help) \
(str, po::value<string>(&option), help)

#define MLOCK_HELP \
"Avoid paging out the process memory during execution."

#define RESTORABLE_APP_HELP \
"Configure package-manager for this comma separate list of Restorable Apps. "  \
"If it is not specified, but a system image is preloaded with Restorable "     \
"Apps then the Restorable App list is set to an empty list which means "       \
"turning restorable App usage ON and the resultant list will be equal to the " \
"apps list. Restorable App list = UNION(compose-apps, restorable-apps)"

#define UUID_HELP \
"A per-device UUID. If not provided, one will be generated. This is "          \
"associated with the device, e.g. as the CommonName field in certificates "    \
"related to it."

#define OSTREE_SRV_HELP \
"Use OSTree Proxy server instead of the Device Gateway to pull the ostree repo."

#define NAME_HELP \
"The name of the device as it should appear in the dashboard. When not "       \
"specified, the device's UUID will be used instead."

#define API_TOKEN_HELP \
"API token for authentication. If not provided, oauth2 will be used instead."

#define APPS_HELP \
"Configure package-manager for this comma separate list of apps."

#define TAGS_HELP \
"Configure " SOTA_CLIENT " to only apply updates from Targets with these tags."

#define DAEMON_HELP \
"Start the " SOTA_CLIENT " systemd service after registration."

#define SOTA_DIR_HELP \
"The directory to install to keys and configuration to."

#define API_TOKEN_HDR_HELP \
"The HTTP header to use for authentication."

#define HWID_HELP \
"The hardware identifier for the device type."

#define DEVICE_GROUP_HELP \
"Assign this device to a device group."

#define PRODUCTION_HELP \
"Mark the device as a production device."

#define FACTORY_HELP \
"The factory name to subscribe to."

#define HSM_SO_PIN_HELP \
"The PKCS#11 security officer pin - HSM only."

#define HSM_HELP \
"The PKCS#11 implementation (.so library) - HSM only."

#define HSM_PIN_HELP \
"The PKCS#11 pin - HSM only."

static void get_factory_tags_info(const string os_release, string &factory,
				  string &tag)
{
	const char *env = std::getenv(ENV_DEVICE_FACTORY);
	ptree os_info;

	if (env != nullptr) {
		cout << "Factory read from environment" << endl;
		factory = env;
	}

	if (!boost::filesystem::exists(os_release))
		return;

	try {
		read_ini(os_release, os_info);
	} catch (boost::property_tree::ini_parser_error const &) {
		cout << "Can't parse file " << os_release << endl;
	}

	try {
		tag = os_info.get<std::string>(OS_FACTORY_TAG);
		boost::algorithm::erase_all(tag, "\"");
		cout << "Tag read from " << os_release << endl;
	} catch (boost::property_tree::ptree_bad_path const &) {
		cout << "Can't read tag from " << os_release << endl;
	}

	if (!factory.empty())
		return;

	try {
		factory = os_info.get<std::string>(OS_FACTORY);
		boost::algorithm::erase_all(factory, "\"");
		cout << "Factory read from " << os_release << endl;
	} catch (boost::property_tree::ptree_bad_path const &) {
		cout << "Can't read factory from " << os_release << endl;
	}
}

static void set_default_options(lmp_options &opt, string factory, string tags,
				po::options_description &desc)
{
	bool prod = false;

#if defined PRODUCTION
	prod = true;
#endif
	desc.add_options()

	("help", "print usage")
	OPT_DEF_BOOL("use-ostree-server", opt.use_server, true, OSTREE_SRV_HELP)
	OPT_DEF_BOOL("production,p", opt.production, prod, PRODUCTION_HELP)
	OPT_DEF_BOOL("start-daemon", opt.start_daemon,true, DAEMON_HELP)
	OPT_DEF_STR("sota-dir,d", opt.sota_dir, SOTA_DIR, SOTA_DIR_HELP)
	OPT_STR("device-group,g", opt.device_group, DEVICE_GROUP_HELP)
	OPT_DEF_STR("factory,f", opt.factory, factory, FACTORY_HELP)
	OPT_STR("hsm-so-pin,S", opt.hsm_so_pin, HSM_SO_PIN_HELP)
	OPT_DEF_BOOL("mlock-all,l", opt.mlock, true, MLOCK_HELP)
	OPT_DEF_STR("hwid,i", opt.hwid, HARDWARE_ID, HWID_HELP)
	OPT_DEF_STR("tags,t", opt.pacman_tags, tags, TAGS_HELP)
	OPT_STR("api-token,T", opt.api_token, API_TOKEN_HELP)
	OPT_STR("hsm-module,m", opt.hsm_module, HSM_HELP)
	OPT_STR("hsm-pin,P", opt.hsm_pin, HSM_PIN_HELP)
	OPT_STR("uuid,u", opt.uuid, UUID_HELP)
	OPT_STR("name,n", opt.name, NAME_HELP)
	OPT_DEF_STR("api-token-header,H",
		    opt.api_token_header, "OSF-TOKEN",API_TOKEN_HDR_HELP)

#if defined DOCKER_COMPOSE_APP
	OPT_STR("apps,a", opt.apps, APPS_HELP)
	/*
	 * Enabled by default, list == compose_apps (or all Target apps)
	 *
	 * --restorable-apps "app-01[,app-02]"
	 *       enable
	 *       list == UNION(compose_apps, app-01[,app-02])
	 *
	 * --restorable-apps ""
	 *       disable
	 */
	OPT_DEF_STR("restorable-apps,A", opt.restorable_apps," ",
		    RESTORABLE_APP_HELP)
#endif
	;
}

static int parse_command_line(int argc, char **argv,
			       po::options_description &desc)
{
	po::options_description all("lmp-device-register all options");
	po::variables_map vm;

	all.add(desc);
	try {
		po::store(
			po::parse_command_line(
				argc,
				reinterpret_cast<const char *const *>(argv),
				all),
			vm);

		if (vm.count("help")) {
			cout << desc;
			cout << "Git Commit " << GIT_COMMIT << endl;
			return -1;
		}
		po::notify(vm);
	} catch (const po::error &o) {
		cout << "ERROR: " << o.what() << endl;
		cout << endl << desc << endl;
		return -1;
	}

	return 0;
}

static void get_uuid(lmp_options &opt)
{
	boost::uuids::uuid tmp;

	/* Use PKCS#11 if the hsm_module was configured */
	if (pkcs11_get_uuid(opt))
		cerr << "WARN: can't get UUID from PKCS token" << endl;

	if (opt.uuid.empty()) {
		tmp = boost::uuids::random_generator()();
		opt.uuid = boost::uuids::to_string(tmp);
		cout << "UUID: " << opt.uuid <<" [Random]" << endl;
	}
}

int options_parse(int argc, char **argv, lmp_options &opt)
{
	po::options_description desc("lmp-device-register options");
	string factory;
	string tags;

	/* Read from environment or configuration file */
	get_factory_tags_info(LMP_OS_STR, factory, tags);

	set_default_options(opt, factory, tags, desc);

	/* Command line takes precedence over any parameters */
	if (parse_command_line(argc, argv, desc))
		return -1;

	if (opt.factory.empty()) {
		cerr << "Missing factory definition" << endl;
		return -1;
	}

	if (opt.pacman_tags.empty()) {
		cerr << "Missing tag definition" << endl;
		return -1;
	}

	if (!opt.hsm_module.empty())
		if (opt.hsm_so_pin.empty() || opt.hsm_pin.empty()) {
			cerr << "HSM incorrectly configured" << endl;
			return -1;
		}

	if (opt.hsm_module.empty())
		if (!opt.hsm_so_pin.empty() ||
		    !opt.hsm_pin.empty()) {
			cerr <<  "HSM incorrectly configured" << endl;
			return -1;
		}

	/* Production env ENABLED takes precedence over config disabled */
	opt.production = std::getenv(ENV_PRODUCTION) != nullptr ?
			true : opt.production;

	/* Set the UUID from OS-Release, HSM or RNG */
	if (opt.uuid.empty())
		get_uuid(opt);

	/* Validate the UUID early to avoid HTTP 400 */
	std::regex UUID("^"
		"[a-fA-F0-9]{8}-"
		"[a-fA-F0-9]{4}-"
		"[a-fA-F0-9]{4}-"
		"[a-fA-F0-9]{4}-"
		"[a-fA-F0-9]{12}"
		"$");
	std::smatch match;
	std::regex_search(opt.uuid, match, UUID);
	if (match.size() <= 0) {
		cerr << "Invalid UUID: " << opt.uuid << endl;
		return -1;
	}

	/* Set the factory name from the UUID if not speficied */
	if (opt.name.empty()) {
		cout << "Setting factory name to UUID " << endl;
		opt.name = opt.uuid;
	}

	if (opt.mlock) {
		if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
			cout << "Error locking memory " << endl;
			return -1;
		}
	}

	cout << "PID memory " << (opt.mlock ? "locked" : "unlocked") <<  endl;

	return 0;
}

/*
 * Copyright (c) 2023 Foundries.io
 *
 * SPDX-License-Identifier: MIT
 */

#include <device_register.h>
#include <errno.h>
#include <signal.h>

namespace po = boost::program_options;
namespace io = boost::iostreams;

static lmp_options opt;

static void spawn(const string &cmd)
{
	g_autofree gchar *out{nullptr};
	g_autofree gchar *err{nullptr};
	g_autofree GError *e{nullptr};
	gint status;

	if (!g_spawn_command_line_sync(cmd.c_str(), &out, &err, &status, &e)) {
		cerr << "Unable to run: " << cmd << endl;
		cerr << "Error is: " << e->message << endl;
		return;
	}

	if (status != 0) {
		cerr << "Unable to run: " << cmd << endl;
		cerr << "STDERR is: " << err << endl;
		return;
	}

	if (e != nullptr) {
		cerr << "Unable to run: " << cmd << endl;
		return;
	}
}

static bool ends_with(const std::string &s, const std::string &suffix)
{
	string::size_type sufsz = suffix.size();
	string::size_type ssz = s.size();

	return ssz >= sufsz && !s.compare(ssz - sufsz, sufsz, suffix);
}

static int sota_cleanup(lmp_options &opt)
{
	string crt = opt.sota_dir + SOTA_PEM;
	string sql = opt.sota_dir + SOTA_SQL;

	cout << "Cleaning up SOTA files" << endl;

	if (!access(sql.c_str(), F_OK)) {
		cout << "Removing " << sql << endl;

		if (unlink(sql.c_str())) {
			cerr << "ERROR: unable to remove " << sql << ": "
			     << strerror(errno) << endl;
			return -1;
		}
	}

	if (!access(crt.c_str(), F_OK)) {
		cout << "Removing " << crt << endl;

		if (unlink(crt.c_str())) {
			cerr << "ERROR: unable to remove " << crt << ": "
			     << strerror(errno) << endl;
			return -1;
		}
	}

	return 0;
}

static int check_sota_files(lmp_options &opt)
{
	string crt = opt.sota_dir + SOTA_PEM;
	string sql = opt.sota_dir + SOTA_SQL;

	if (access(sql.c_str(), F_OK) && access(crt.c_str(), F_OK))
		return 0;

	if (!opt.force) {
		cerr << "ERROR: Device already registered in "
		     << opt.sota_dir << endl;
		cerr << "Re-run with --force 1 to remove existing registration "
		     << "data" << endl;
		return -1;
	}

	return sota_cleanup(opt);
}

static int check_aklite_not_running()
{
	const char *const aklock{AKLITE_LOCK};

	if (!boost::filesystem::exists(aklock))
		return 0;

	boost::interprocess::file_lock lock{aklock};
	try {
		if (lock.try_lock_sharable())
			return 0;

		cerr << "ERROR: " SOTA_CLIENT " already running" << endl;
		return -1;
	} catch (...) {
		cerr << "ERROR: is " SOTA_CLIENT " running ?" << endl;
		return -1;
	}
}

static int check_device_status(lmp_options &opt)
{
	string tmp = opt.sota_dir + "/.tmp";

	/* Check directory is writable */
	int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC,
		      S_IRUSR | S_IWUSR);
	if (fd < 0) {
		cerr << "Unable to write to " << opt.sota_dir << endl;
		return -1;
	}

	close(fd);
	unlink(tmp.c_str());

	/* Aklite must not be running */
	if (check_aklite_not_running())
		return -1;

	/* Check device was not been registered */
	if (check_sota_files(opt))
		return -1;

	return 0;
}

static void put_compose_app_info(const lmp_options &opt, ptree &dev)
{
#ifdef DOCKER_COMPOSE_APP
	string reset_apps = opt.sota_dir + "/reset-apps";
	string apps = opt.sota_dir + "/compose-apps";

	dev.put("overrides.pacman.type", "\"ostree+compose_apps\"");
	dev.put("overrides.pacman.compose_apps_root", "\"" + apps + "\"");
	if (!opt.apps.empty()) {
		string str("overrides.pacman.compose_apps");
		dev.put(str, "\"" + opt.apps + "\"");
	}


	dev.put("overrides.pacman.reset_apps_root", "\"" + reset_apps + "\"");
	if (!opt.restorable_apps.empty()) {
		string str("overrides.pacman.reset_apps");
		dev.put(str, "\"" + opt.restorable_apps + "\"");
		return;
	}

	/*
	 * If restorable-apps was not specified but a system image is
	 * preloaded with them, force restorable-apps ON
	 */
	if (boost::filesystem::exists(reset_apps)) {
		cout << "Device is preloaded with Restorable Apps,"
			" turning their usage ON" << endl;

		dev.put("overrides.pacman.reset_apps", "\"\"");
	}
#endif
}

static void put_hsm_info(const lmp_options &opt, ptree &dev)
{
	if (opt.hsm_module.empty())
		return;

	dev.put("overrides.tls.pkey_source", "\"pkcs11\"");
	dev.put("overrides.tls.cert_source", "\"pkcs11\"");
	dev.put("overrides.storage.tls_pkey_path", "");
	dev.put("overrides.storage.tls_clientcert_path", "");
	dev.put("overrides.import.tls_pkey_path", "");
	dev.put("overrides.import.tls_clientcert_path", "");
}

static void get_device_info(const lmp_options &opt, string &csr, ptree &dev)
{
	/* Device */
	dev.put<bool>("use-ostree-server", opt.use_server);
	dev.put("sota-config-dir", opt.sota_dir);
	dev.put("hardware-id", opt.hwid);
	dev.put("name", opt.name);
	dev.put("uuid", opt.uuid);
	dev.put("csr", csr);

	/* HSM information */
	put_hsm_info(opt, dev);

	/* Compose apps information */
	put_compose_app_info(opt, dev);

	if (!opt.device_group.empty())
		dev.put("group", opt.device_group);

	if (!opt.pacman_tags.empty())
		dev.put("overrides.pacman.tags", "\"" + opt.pacman_tags + "\"");
}

static int write_safely(const string &name, const string &content)
{
	auto tmp = name + ".tmp";

	try {
		io::stream<boost::iostreams::file_descriptor_sink> file(tmp);
		file << content;
		file.flush();
		int rc = fsync(file->handle());
		if (rc != 0) {
			cerr << "Unable to write to " << tmp <<
				": " << strerror(errno) << endl;
			return -1;
		}
	} catch (const std::exception &e) {
		cerr << "Unable to open " << tmp <<
			" for writing: " << e.what() << endl;
		return -1;
	}
	int rc = rename(tmp.c_str(), name.c_str());
	if (rc != 0) {
		cerr << "Unable to create " << name <<
			": " << strerror(errno) << endl;
		return -1;
	}

	return 0;
}

/*
 * We additionally write the entire p11 section. We can't tell the server the
 * PIN, and don't want to parse/modify TOML to add it, so just write the whole
 * thing to /var/sota/
 */
static void fill_p11_engine_info(lmp_options &opt, stringstream &sota_toml)
{
	sota_toml << "[p11]" << endl;
	sota_toml << "module = \"" << opt.hsm_module << "\"" << endl;
	sota_toml << "pass = \"" << opt.hsm_pin << "\"" << endl;
	sota_toml << "tls_pkey_id = \"" <<  HSM_TLS_ID_STR << "\"" << endl;
	sota_toml << "tls_clientcert_id = \"" << HSM_CRT_ID_STR << "\"" << endl;
	sota_toml << endl;
}

static int populate_sota_dir(lmp_options &opt, ptree &resp, string &pkey)
{
	cout << "Populate sota directory." << endl;

	if (opt.hsm_module.empty()) {
		/* Write the private key */
		std::ofstream out(opt.sota_dir + "/pkey.pem");
		out << pkey;
		out.close();
	}

	stringstream sota_toml;
	for (auto it: resp) {
		string name = opt.sota_dir + "/" + it.first;

		if (ends_with(name, "sota.toml")) {
			sota_toml << it.second.data() << endl;

			if (!opt.hsm_module.empty())
				fill_p11_engine_info(opt, sota_toml);

			continue;
		}

		if (write_safely(name, it.second.data()))
			goto error;

		if (!ends_with(name, ".pem"))
			continue;

		/* Import the certificate also to PKCS#11 database */
		if (!opt.hsm_module.empty()) {
			/* Read back the file into X509 */
			FILE *file = NULL;
			X509 *crt = NULL;

			file = fopen(name.c_str(), "rb");
			if (!file)
				goto error;

			crt = PEM_read_X509(file, NULL, 0, NULL);
			if (!crt)
				goto error;

			fclose(file);

			if (pkcs11_store_cert(opt, crt))
				goto error;
		}
	}

	if (write_safely(opt.sota_dir + "/sota.toml", sota_toml.str()))
		goto error;

	return 0;
error:
	sota_cleanup(opt);

	return -1;
}

/*
 * Create a Certificate Signing Request
 */
int create_csr(const lmp_options &opt, string &key, string &csr)
{
	if (opt.hsm_module.empty())
		return openssl_create_csr(opt, key, csr);

	return pkcs11_create_csr(opt, key, csr);
}

static void cleanup(void)
{
	cout << "Cleaning up partial registration before leaving" << endl;
	sota_cleanup(opt);
	pkcs11_cleanup(opt);
}

static void sig_handler(int signum)
{
	cout << endl << "Handling " << strsignal(signum) << " signal" << endl;

	/* Re-register default signal handler */
	signal(signum, SIG_DFL);

	cleanup();

	/* Call default signal handler */
	raise(signum);
}

static void set_signals(sighandler_t handler)
{
	signal(SIGINT, sig_handler);
	signal(SIGSEGV, sig_handler);
}

int main(int argc, char **argv)
{
	http_headers headers{{ "Content-type", "application/json" }};
	ptree info;
	ptree resp;
	string key;
	string csr;

	if (options_parse(argc, argv, opt))
		return -1;

	/* Check if this device can be registered */
	if (check_device_status(opt))
		return -1;

	/* Get the HTTP headers */
	if (auth_get_http_headers(opt, headers))
		return -1;

	/* Check that the registration server and endpoint are reachable */
	if (auth_ping_server())
		return -1;

	/* Register signal handler for cleaning up */
	set_signals(sig_handler);

	/* Create the key pair and the certificate request */
	if (create_csr(opt, key, csr))
		goto error;

	/* Get the device information */
	get_device_info(opt, csr, info);

	/* Register the device with the factory */
	cout << "Registering device " << opt.name <<
		" with factory " << opt.factory << endl;

	if (auth_register_device(headers, info, resp))
		goto error;

	/* Store the login details */
	if (populate_sota_dir(opt, resp, key))
		goto error;

	/* No need for cleanup on signals after this point */
	set_signals(SIG_DFL);

	cout << "Device is now registered." << endl;
	if (opt.start_daemon) {
		cout << "Starting " SOTA_CLIENT " daemon" << endl;
		spawn("systemctl start " SOTA_CLIENT);
	}

	return 0;
error:
	set_signals(SIG_DFL);
	cleanup();

	return -1;
}

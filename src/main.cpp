#include <iostream>
#include <string>

#include <boost/program_options.hpp>

namespace po = boost::program_options;
using std::cerr;
using std::cout;
using std::endl;
using std::string;

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

int main(int argc, char **argv)
{
	string stream, hwid, name;
	if (!_get_options(argc, argv, stream, hwid, name))
		return EXIT_FAILURE;

	cout << "Registering device, " << name << ", to stream " << stream << "." << endl;

	return EXIT_SUCCESS;
}

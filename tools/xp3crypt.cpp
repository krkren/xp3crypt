// xp3crypt.cpp - the command-line tool. It makes keys, packs a folder into an encrypted XP3
// archive, and writes or reads the key in an engine (or plugin) binary.
//
//   xp3crypt keygen  <keyfile>
//   xp3crypt pack    <folder> <out.xp3>   (--key <hex> | --keyfile <path>)
//   xp3crypt setkey  <binary>             (--key <hex> | --keyfile <path>)
//   xp3crypt readkey <binary>
//   xp3crypt check   <binary>
//
// SPDX-License-Identifier: 0BSD

#include "xp3crypt.hpp"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

int usage() {
	std::cerr <<
	    "xp3crypt - encrypted XP3 archives for Kirikiri Z\n\n"
	    "  xp3crypt keygen  <keyfile>                      make a new random key\n"
	    "  xp3crypt pack    <folder> <out.xp3> --keyfile <path>   pack, encrypted\n"
	    "  xp3crypt setkey  <binary> --keyfile <path>      write the key into a binary's slot\n"
	    "  xp3crypt readkey <binary>                       print the key in a binary\n"
	    "  xp3crypt check   <binary>                       report the slot and key\n\n"
	    "A key is 64 hexadecimal digits. Give it with --keyfile <path> or --key <hex>.\n";
	return 2;
}

bool readFile(const fs::path &p, std::string &out) {
	std::ifstream f(p, std::ios::binary);
	if (!f) return false;
	std::ostringstream ss;
	ss << f.rdbuf();
	out = ss.str();
	return true;
}

bool writeFile(const fs::path &p, const std::string &data) {
	std::ofstream f(p, std::ios::binary | std::ios::trunc);
	if (!f) return false;
	f.write(data.data(), std::streamsize(data.size()));
	return bool(f);
}

// --key <hex> or --keyfile <path> among the args; exactly one
bool keyFromArgs(const std::vector<std::string> &args, xp3crypt::Key &key, std::string &error) {
	std::string hex, file;
	for (size_t i = 0; i < args.size(); i++) {
		if (args[i] == "--key" && i + 1 < args.size()) hex = args[++i];
		else if (args[i] == "--keyfile" && i + 1 < args.size()) file = args[++i];
	}
	if (hex.empty() == file.empty()) { error = "give the key with exactly one of --key <hex> or --keyfile <path>"; return false; }
	if (!hex.empty()) return xp3crypt::parseKey(hex, key, error);
	std::string text;
	if (!readFile(file, text)) { error = "can't read the key file " + file; return false; }
	return xp3crypt::parseKey(text, key, error);
}

int keygen(const std::vector<std::string> &rest) {
	if (rest.empty()) return usage();
	const fs::path file = rest[0];
	std::error_code ec;
	if (fs::exists(file, ec)) { std::cerr << file.string() << " already exists; a key isn't replaced by mistake\n"; return 1; }
	try {
		xp3crypt::Key key = xp3crypt::randomKey();
		const std::string text = xp3crypt::formatKey(key) + "\n";
		xp3crypt::wipe(key);
		if (!writeFile(file, text)) { std::cerr << "can't write " << file.string() << "\n"; return 1; }
	} catch (const std::exception &e) {
		std::cerr << e.what() << "\n";
		return 1;
	}
	std::cout << "wrote a new key to " << file.string() << "\n";
	return 0;
}

int pack(const std::vector<std::string> &rest) {
	std::vector<std::string> pos;
	for (size_t i = 0; i < rest.size(); i++) {
		if (rest[i] == "--key" || rest[i] == "--keyfile") { i++; continue; }
		pos.push_back(rest[i]);
	}
	if (pos.size() < 2) return usage();
	xp3crypt::Key key;
	std::string error;
	if (!keyFromArgs(rest, key, error)) { std::cerr << error << "\n"; return 1; }

	xp3crypt::PackResult result;
	xp3crypt::PackOptions opt;
	const bool ok = xp3crypt::pack(pos[0], pos[1], key, opt, result, error,
	    [](const std::string &name, uint64_t, uint64_t) { std::cout << "  " << name << "\n"; return true; });
	xp3crypt::wipe(key);
	if (!ok) { std::cerr << "pack failed: " << error << "\n"; return 1; }
	std::cout << "packed " << result.files << " files into " << pos[1] << " ("
	          << (result.arcBytes / 1024) << " KB)\n";
	return 0;
}

int setkey(const std::vector<std::string> &rest) {
	std::vector<std::string> pos;
	for (size_t i = 0; i < rest.size(); i++) {
		if (rest[i] == "--key" || rest[i] == "--keyfile") { i++; continue; }
		pos.push_back(rest[i]);
	}
	if (pos.empty()) return usage();
	xp3crypt::Key key;
	std::string error;
	if (!keyFromArgs(rest, key, error)) { std::cerr << error << "\n"; return 1; }
	std::string bytes;
	if (!readFile(pos[0], bytes)) { std::cerr << "can't read " << pos[0] << "\n"; xp3crypt::wipe(key); return 1; }
	std::vector<uint8_t> bin(bytes.begin(), bytes.end());
	const int n = xp3crypt::writeSlots(bin, key, error);
	xp3crypt::wipe(key);
	if (n == 0) { std::cerr << pos[0] << ": " << error << "\n"; return 1; }
	if (!writeFile(pos[0], std::string(bin.begin(), bin.end()))) { std::cerr << "can't write " << pos[0] << "\n"; return 1; }
	std::cout << "wrote the key into " << n << (n == 1 ? " slot" : " slots") << " of " << pos[0] << "\n";
	return 0;
}

int readkey(const std::vector<std::string> &rest) {
	if (rest.empty()) return usage();
	std::string bytes;
	if (!readFile(rest[0], bytes)) { std::cerr << "can't read " << rest[0] << "\n"; return 1; }
	xp3crypt::Key key;
	std::string error;
	const bool have = xp3crypt::readSlot(reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size(), key, error);
	if (!error.empty()) { std::cerr << rest[0] << ": " << error << "\n"; return 1; }
	if (!have) { std::cout << "no key is set in " << rest[0] << "\n"; return 0; }
	std::cout << xp3crypt::formatKey(key) << "\n";
	xp3crypt::wipe(key);
	return 0;
}

int check(const std::vector<std::string> &rest) {
	if (rest.empty()) return usage();
	std::string bytes;
	if (!readFile(rest[0], bytes)) { std::cerr << "can't read " << rest[0] << "\n"; return 1; }
	std::string error;
	const auto slots = xp3crypt::findSlots(reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size(), error);
	if (!error.empty()) { std::cerr << rest[0] << ": " << error << "\n"; return 1; }
	if (slots.empty()) { std::cout << rest[0] << ": no xp3crypt key slot\n"; return 1; }
	xp3crypt::Key key;
	const bool have = xp3crypt::readSlot(reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size(), key, error);
	xp3crypt::wipe(key);
	std::cout << rest[0] << ": " << slots.size() << (slots.size() == 1 ? " slot" : " slots") << ", "
	          << (have ? "a key is set" : "no key set") << "\n";
	return 0;
}

} // namespace

int main(int argc, char **argv) {
	std::vector<std::string> args(argv + 1, argv + argc);
	if (args.empty()) return usage();
	const std::string cmd = args[0];
	const std::vector<std::string> rest(args.begin() + 1, args.end());
	if (cmd == "keygen") return keygen(rest);
	if (cmd == "pack") return pack(rest);
	if (cmd == "setkey") return setkey(rest);
	if (cmd == "readkey") return readkey(rest);
	if (cmd == "check") return check(rest);
	return usage();
}

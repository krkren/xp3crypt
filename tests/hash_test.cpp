// hash_test.cpp - hashed-name packing and the index reader: pack with hashNames, read the index
// back with xp3crypt::readIndex, and check each stored name is the keyed hash of its path and
// that the content still decrypts.
//
// SPDX-License-Identifier: 0BSD

#include "xp3crypt.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace xp3crypt;

static int failures = 0;
#define CHECK(c) do { if (!(c)) { std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

static void writeFile(const fs::path &p, const std::vector<uint8_t> &d) {
	fs::create_directories(p.parent_path());
	std::ofstream f(p, std::ios::binary | std::ios::trunc);
	f.write(reinterpret_cast<const char *>(d.data()), std::streamsize(d.size()));
}

int main() {
	Key key;
	for (size_t i = 0; i < key.size(); i++) key[i] = uint8_t(i * 9 + 2);

	// hashName: deterministic, 32 hex digits, and normalization (case, backslashes) folds in
	CHECK(hashName(key, "scenario/first.ks").size() == 32);
	CHECK(hashName(key, "scenario/first.ks") == hashName(key, "scenario/first.ks"));
	CHECK(hashName(key, "Scenario\\First.KS") == hashName(key, "scenario/first.ks"));
	CHECK(hashName(key, "a/b") != hashName(key, "a/c"));
	Key other;
	for (size_t i = 0; i < other.size(); i++) other[i] = uint8_t(i + 1);
	CHECK(hashName(key, "a/b") != hashName(other, "a/b"));   // keyed: differs per game

	const std::string tag = std::to_string((long long)std::chrono::steady_clock::now().time_since_epoch().count());
	const fs::path dir = fs::temp_directory_path() / ("xp3crypt_hash_" + tag);
	std::error_code ec;
	fs::remove_all(dir, ec);

	std::map<std::string, std::vector<uint8_t>> originals;
	auto make = [&](const std::string &name, size_t n) {
		std::vector<uint8_t> v(n);
		for (size_t i = 0; i < n; i++) v[i] = uint8_t(i * 41 + name.size() + 3);
		writeFile(dir / name, v);
		originals[name] = v;
	};
	make("first.ks", 100);
	make("scenario/s0001.ks", 4096);
	make("image/bg.png", 7000);

	const fs::path arc = fs::temp_directory_path() / ("xp3crypt_hash_" + tag + ".xp3");
	PackOptions opt;
	opt.hashNames = true;
	opt.compressIndex = false;   // the plugin reads the index without zlib
	PackResult result;
	std::string err;
	CHECK(pack(dir, arc, key, opt, result, err, {}));
	CHECK(err.empty());
	CHECK(result.files == (int)originals.size());

	// the archive holds no plaintext path
	std::ifstream in(arc, std::ios::binary);
	const std::string bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	in.close();
	CHECK(bytes.find("first.ks") == std::string::npos);
	CHECK(bytes.find("s0001.ks") == std::string::npos);

	// read the index back through xp3crypt::readIndex, and resolve each original by its hash
	std::vector<IndexEntry> entries;
	CHECK(readIndex(
		[&](uint64_t off, void *buf, size_t len) { std::memcpy(buf, bytes.data() + off, len); },
		bytes.size(), entries, err));
	CHECK(err.empty());
	CHECK(entries.size() == originals.size() + 1);   // + the name manifest

	std::map<std::string, IndexEntry> byHash;
	for (const auto &e : entries) {
		CHECK(e.name.size() == 32);   // a hash, not a path
		byHash[e.name] = e;
	}

	// the manifest decrypts to the real paths, one per line
	{
		const auto it = byHash.find(manifestName(key));
		CHECK(it != byHash.end());
		if (it != byHash.end()) {
			std::vector<uint8_t> blob(bytes.begin() + it->second.offset, bytes.begin() + it->second.offset + it->second.size);
			xorFile(blob.data(), blob.size(), 0, it->second.fileHash, key);
			const std::string text(blob.begin(), blob.end());
			for (const auto &[name, data] : originals) CHECK(text.find(name + "\n") != std::string::npos);
		}
	}
	for (const auto &[name, data] : originals) {
		const auto it = byHash.find(hashName(key, name));
		CHECK(it != byHash.end());
		if (it == byHash.end()) continue;
		std::vector<uint8_t> blob(bytes.begin() + it->second.offset, bytes.begin() + it->second.offset + it->second.size);
		xorFile(blob.data(), blob.size(), 0, it->second.fileHash, key);
		CHECK(blob == data);
		// a partway read decrypts too (the medium reads at arbitrary offsets)
		if (data.size() > 100) {
			std::vector<uint8_t> part(bytes.begin() + it->second.offset + 64, bytes.begin() + it->second.offset + 164);
			xorFile(part.data(), part.size(), 64, it->second.fileHash, key);
			CHECK(std::memcmp(part.data(), data.data() + 64, 100) == 0);
		}
	}

	// plainNames: a path kept under its own name (a startup.tjs the engine's own XP3 mount finds),
	// still encrypted and out of the manifest; saltBase: the salts start past it
	{
		const fs::path arc2 = fs::temp_directory_path() / ("xp3crypt_hash_" + tag + "_plain.xp3");
		make("startup.tjs", 300);
		PackOptions o2;
		o2.hashNames = true;
		o2.compressIndex = false;
		o2.plainNames = { "startup.tjs" };
		o2.saltBase = 0x01000000;
		PackResult r2;
		CHECK(pack(dir, arc2, key, o2, r2, err, {}));
		std::ifstream in2(arc2, std::ios::binary);
		const std::string b2((std::istreambuf_iterator<char>(in2)), std::istreambuf_iterator<char>());
		in2.close();
		std::vector<IndexEntry> e2;
		CHECK(readIndex([&](uint64_t off, void *buf, size_t len) { std::memcpy(buf, b2.data() + off, len); }, b2.size(), e2, err));
		CHECK(e2.size() == originals.size() + 1);
		int plain = 0;
		for (const auto &e : e2) {
			CHECK(e.fileHash > 0x01000000u && e.fileHash <= 0x01000000u + uint32_t(e2.size()));
			if (e.name == "startup.tjs") {
				plain++;
				std::vector<uint8_t> blob(b2.begin() + e.offset, b2.begin() + e.offset + e.size);
				CHECK(blob != originals["startup.tjs"]);   // encrypted all the same
				xorFile(blob.data(), blob.size(), 0, e.fileHash, key);
				CHECK(blob == originals["startup.tjs"]);
			} else {
				CHECK(e.name.size() == 32);
			}
			if (e.name == manifestName(key)) {
				std::vector<uint8_t> blob(b2.begin() + e.offset, b2.begin() + e.offset + e.size);
				xorFile(blob.data(), blob.size(), 0, e.fileHash, key);
				const std::string text(blob.begin(), blob.end());
				CHECK(text.find("startup.tjs") == std::string::npos);
				CHECK(text.find("scenario/s0001.ks\n") != std::string::npos);
			}
		}
		CHECK(plain == 1);
		CHECK(b2.find("s0001.ks") == std::string::npos);
		fs::remove(arc2, ec);
	}

	fs::remove_all(dir, ec);
	fs::remove(arc, ec);
	wipe(key);
	if (failures == 0) std::printf("hash_test: all passed\n");
	return failures ? 1 : 0;
}

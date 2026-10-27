// names_test.cpp - file names beyond ASCII and in mixed case. Packing takes names through UTF-8
// (path::string() goes through the ANSI code page on Windows, and throws on a name outside it),
// the index holds them as UTF-16 and reads back as the same UTF-8, and a hashed archive's
// manifest lists them in lower case (ASCII), as the engine's XP3 reader lists an archive, with
// every listed name still hashing to its file.
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
#include <set>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace xp3crypt;

static int failures = 0;
#define CHECK(c) do { if (!(c)) { std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

// The names in UTF-8, spelt out so the test doesn't depend on the compiler's source charset
static const std::string ITEM = "\xe3\x82\xa2\xe3\x82\xa4\xe3\x83\x86\xe3\x83\xa0_\xe6\xa4\x85\xe5\xad\x90";   // "item_chair" in Japanese
static const std::string WHITE = "\xe7\x94\xbb\xe9\x9d\xa2_\xe7\x99\xbd";   // "screen_white"
static const std::string VOICE = "\xe9\x9f\xb3\xe5\xa3\xb0";                // "voice"
static const std::string NOTE = "\xf0\x9f\x8e\xb5";                         // U+1F3B5, a surrogate pair in UTF-16
static const std::string FULL_A = "\xef\xbc\xa1";                           // U+FF21, a full-width capital A

static void writeFile(const fs::path &p, const std::vector<uint8_t> &d) {
	fs::create_directories(p.parent_path());
	std::ofstream f(p, std::ios::binary | std::ios::trunc);
	f.write(reinterpret_cast<const char *>(d.data()), std::streamsize(d.size()));
}

static std::string readAll(const fs::path &p) {
	std::ifstream in(p, std::ios::binary);
	return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

static std::vector<IndexEntry> readEntries(const std::string &bytes, std::string &err) {
	std::vector<IndexEntry> entries;
	CHECK(readIndex([&](uint64_t off, void *buf, size_t len) { std::memcpy(buf, bytes.data() + off, len); },
	                bytes.size(), entries, err));
	return entries;
}

static std::vector<uint8_t> contents(const std::string &bytes, const IndexEntry &e, const Key &key) {
	std::vector<uint8_t> blob(bytes.begin() + e.offset, bytes.begin() + e.offset + e.size);
	xorFile(blob.data(), blob.size(), 0, e.fileHash, key);
	return blob;
}

static std::string lower(std::string s) {
	for (char &c : s) if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
	return s;
}

int main() {
	Key key;
	for (size_t i = 0; i < key.size(); i++) key[i] = uint8_t(i * 7 + 5);

	// the path helpers: UTF-8 in, the same UTF-8 out, '/'-separated
	CHECK(pathToUtf8(utf8ToPath(VOICE + "/" + NOTE + ".ogg")) == VOICE + "/" + NOTE + ".ogg");
	CHECK(pathToUtf8(utf8ToPath("a") / utf8ToPath(WHITE)) == "a/" + WHITE);

	const std::string tag = std::to_string((long long)std::chrono::steady_clock::now().time_since_epoch().count());
	const fs::path dir = fs::temp_directory_path() / ("xp3crypt_names_" + tag);
	std::error_code ec;
	fs::remove_all(dir, ec);

	std::map<std::string, std::vector<uint8_t>> originals;
	auto make = [&](const std::string &name, size_t n) {
		std::vector<uint8_t> v(n);
		for (size_t i = 0; i < n; i++) v[i] = uint8_t(i * 13 + name.size() + 7);
		writeFile(dir / utf8ToPath(name), v);
		originals[name] = v;
	};
	make("bgimage/" + ITEM + ".png", 300);
	make("Image/" + WHITE + ".PNG", 500);       // a folder and an extension in upper case
	make(VOICE + "/" + NOTE + ".ogg", 200);
	make("Readme.TXT", 50);

	// a plain archive: every name stored as it is (the engine lower-cases them as it reads)
	{
		const fs::path arc = fs::temp_directory_path() / ("xp3crypt_names_" + tag + ".xp3");
		PackOptions opt;
		opt.compressIndex = false;
		PackResult result;
		std::string err;
		std::set<std::string> progressed;
		CHECK(pack(dir, arc, key, opt, result, err,
		           [&](const std::string &name, uint64_t, uint64_t) { progressed.insert(name); return true; }));
		CHECK(err.empty());
		CHECK(result.files == (int)originals.size());
		for (const auto &[name, data] : originals) CHECK(progressed.count(name) == 1);

		const std::string bytes = readAll(arc);
		CHECK(bytes.find("\x3c\xd8\xb5\xdf") != std::string::npos);   // U+1F3B5 as a UTF-16LE surrogate pair
		const auto entries = readEntries(bytes, err);
		CHECK(entries.size() == originals.size());
		for (const auto &e : entries) {
			const auto it = originals.find(e.name);
			CHECK(it != originals.end());
			if (it != originals.end()) CHECK(contents(bytes, e, key) == it->second);
		}
		fs::remove(arc, ec);
	}

	// a hashed archive: the manifest keeps the names as they are, and lists them lower-cased
	{
		const fs::path arc = fs::temp_directory_path() / ("xp3crypt_names_" + tag + "_hash.xp3");
		PackOptions opt;
		opt.compressIndex = false;
		opt.hashNames = true;
		PackResult result;
		std::string err;
		CHECK(pack(dir, arc, key, opt, result, err, {}));
		CHECK(err.empty());
		const std::string bytes = readAll(arc);
		CHECK(bytes.find(WHITE) == std::string::npos);
		const auto entries = readEntries(bytes, err);
		CHECK(entries.size() == originals.size() + 1);
		std::map<std::string, IndexEntry> byHash;
		for (const auto &e : entries) byHash[e.name] = e;

		const auto m = byHash.find(manifestName(key));
		CHECK(m != byHash.end());
		if (m != byHash.end()) {
			const auto blob = contents(bytes, m->second, key);
			const std::string text(blob.begin(), blob.end());
			for (const auto &[name, data] : originals) CHECK(text.find(name + "\n") != std::string::npos);

			const auto folders = manifestFolders(text);
			CHECK(folders.count("image") == 1 && folders.count("Image") == 0);
			auto has = [&](const std::string &folder, const std::string &leaf) {
				const auto f = folders.find(folder);
				return f != folders.end() && std::find(f->second.begin(), f->second.end(), leaf) != f->second.end();
			};
			CHECK(has("image", WHITE + ".png"));
			CHECK(has("bgimage", ITEM + ".png"));
			CHECK(has(VOICE, NOTE + ".ogg"));
			CHECK(has("", "readme.txt"));

			// every listed (lower-case) name resolves by its hash to its file
			size_t listed = 0;
			for (const auto &[folder, leaves] : folders) {
				for (const auto &leaf : leaves) {
					const std::string path = folder.empty() ? leaf : folder + "/" + leaf;
					listed++;
					const auto e = byHash.find(hashName(key, path));
					CHECK(e != byHash.end());
					const auto o = std::find_if(originals.begin(), originals.end(), [&](const auto &kv) { return lower(kv.first) == path; });
					CHECK(o != originals.end());
					if (e != byHash.end() && o != originals.end()) CHECK(contents(bytes, e->second, key) == o->second);
				}
			}
			CHECK(listed == originals.size());
		}
		fs::remove(arc, ec);
	}

	// a plain name in a hashed archive, beyond ASCII: stored as its own UTF-8
	{
		const fs::path arc = fs::temp_directory_path() / ("xp3crypt_names_" + tag + "_plain.xp3");
		PackOptions opt;
		opt.compressIndex = false;
		opt.hashNames = true;
		opt.plainNames = { "bgimage/" + ITEM + ".png" };
		PackResult result;
		std::string err;
		CHECK(pack(dir, arc, key, opt, result, err, {}));
		const std::string bytes = readAll(arc);
		int plain = 0;
		for (const auto &e : readEntries(bytes, err)) {
			if (e.name != "bgimage/" + ITEM + ".png") continue;
			plain++;
			CHECK(contents(bytes, e, key) == originals["bgimage/" + ITEM + ".png"]);
		}
		CHECK(plain == 1);
		fs::remove(arc, ec);
	}

	// only ASCII folds, in the listing as in the hash (folding U+FF21 in one but not the other
	// would list a name that doesn't resolve)
	{
		const auto folders = manifestFolders("A/B/C.PNG\nx\n\nFull" + FULL_A + ".txt");
		CHECK(folders.size() == 2);
		CHECK(folders.count("a/b") && folders.at("a/b") == std::vector<std::string>{ "c.png" });
		CHECK(folders.count("") && folders.at("") == (std::vector<std::string>{ "x", "full" + FULL_A + ".txt" }));
		CHECK(hashName(key, "Full" + FULL_A + ".txt") == hashName(key, "full" + FULL_A + ".txt"));
		CHECK(hashName(key, "full" + FULL_A + ".txt") != hashName(key, "full\xef\xbd\x81.txt"));   // U+FF41, its small form
	}

	fs::remove_all(dir, ec);
	wipe(key);
	if (failures == 0) std::printf("names_test: all passed\n");
	return failures ? 1 : 0;
}

// xp3_test.cpp - packs a folder into an encrypted archive, then reads it back the way the engine
// does (parse the index, read each file's stored bytes, decrypt at the right offset) and checks
// the bytes match. The index is written uncompressed here so the test needs no zlib.
//
// SPDX-License-Identifier: 0BSD

#include "xp3crypt.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
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
#define CHECK(cond) do { if (!(cond)) { std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

static uint16_t rd16(const uint8_t *p) { return uint16_t(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) { return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24); }
static uint64_t rd64(const uint8_t *p) { return uint64_t(rd32(p)) | (uint64_t(rd32(p + 4)) << 32); }

static bool findChunk(const std::vector<uint8_t> &d, size_t from, size_t to, const char *name, size_t &start, size_t &size) {
	size_t pos = from;
	while (pos + 12 <= to) {
		const uint64_t sz = rd64(&d[pos + 4]);
		if (pos + 12 + sz > to) return false;
		if (std::memcmp(&d[pos], name, 4) == 0) { start = pos + 12; size = size_t(sz); return true; }
		pos += 12 + size_t(sz);
	}
	return false;
}

struct Item { std::string name; uint32_t salt; uint64_t start; uint64_t size; };

// Parse the index the way the engine does: follow offset 11 to the (continue) index chain and
// read the raw index bytes
static std::vector<Item> parse(const std::vector<uint8_t> &d, std::string &error) {
	std::vector<Item> items;
	if (d.size() < 11 || d[0] != 'X' || d[1] != 'P' || d[2] != '3') { error = "not an XP3 file"; return items; }
	uint64_t pos = 11;
	std::vector<uint8_t> index;
	for (int guard = 0; guard < 16; guard++) {
		if (pos + 8 > d.size()) { error = "index pointer out of range"; return items; }
		uint64_t ofs = rd64(&d[pos]);
		if (ofs + 1 > d.size()) { error = "index out of range"; return items; }
		const uint8_t flag = d[ofs];
		size_t ip = size_t(ofs) + 1;
		if ((flag & 0x07) == 0) {   // raw
			const uint64_t isize = rd64(&d[ip]);
			ip += 8;
			index.insert(index.end(), d.begin() + ip, d.begin() + ip + isize);
			ip += size_t(isize);
		} else {
			error = "this test writes an uncompressed index";
			return items;
		}
		if (flag & 0x80) { pos = ip; continue; }   // continue: next I64 pointer is here
		break;
	}

	size_t fstart = 0, fsize = index.size(), cs, csz;
	size_t scan = 0;
	while (findChunk(index, scan, index.size(), "File", fstart, fsize)) {
		const size_t fend = fstart + fsize;
		Item it;
		if (!findChunk(index, fstart, fend, "info", cs, csz) || csz < 22) { error = "bad info"; return items; }
		const uint16_t namelen = rd16(&index[cs + 20]);
		std::string name;
		for (uint16_t i = 0; i < namelen; i++) {
			uint16_t c = rd16(&index[cs + 22 + i * 2]);
			if (c < 0x80) name += char(c);
			else name += '?';   // the test uses ASCII names
		}
		it.name = name;
		if (!findChunk(index, fstart, fend, "segm", cs, csz) || csz < 28) { error = "bad segm"; return items; }
		it.start = rd64(&index[cs + 4]);
		it.size = rd64(&index[cs + 12]);
		if (!findChunk(index, fstart, fend, "adlr", cs, csz) || csz < 4) { error = "bad adlr"; return items; }
		it.salt = rd32(&index[cs]);
		items.push_back(it);
		scan = fend;
	}
	return items;
}

static void writeFile(const fs::path &p, const std::vector<uint8_t> &data) {
	fs::create_directories(p.parent_path());
	std::ofstream f(p, std::ios::binary | std::ios::trunc);
	f.write(reinterpret_cast<const char *>(data.data()), std::streamsize(data.size()));
}

int main() {
	Key key;
	for (size_t i = 0; i < key.size(); i++) key[i] = uint8_t(i * 5 + 3);

	const std::string tag = std::to_string((long long)std::chrono::steady_clock::now().time_since_epoch().count());
	const fs::path dir = fs::temp_directory_path() / ("xp3crypt_test_" + tag);
	std::error_code ec;
	fs::remove_all(dir, ec);
	fs::create_directories(dir);

	std::map<std::string, std::vector<uint8_t>> originals;
	auto make = [&](const std::string &name, size_t size) {
		std::vector<uint8_t> v(size);
		for (size_t i = 0; i < size; i++) v[i] = uint8_t((i * 37 + name.size() * 11 + 1) & 0xff);
		writeFile(dir / name, v);
		originals[name] = v;
	};
	make("a.txt", 13);
	make("sub/b.bin", 64);
	make("c.dat", 5000);
	make("empty", 0);
	make("sub/deep/d", 100000);

	const fs::path arc = fs::temp_directory_path() / ("xp3crypt_test_" + tag + ".xp3");
	PackOptions opt;
	opt.compressIndex = false;   // so the test parser needs no zlib
	PackResult result;
	std::string error;
	CHECK(pack(dir, arc, key, opt, result, error, {}));
	CHECK(error.empty());
	CHECK(result.files == (int)originals.size());

	std::ifstream in(arc, std::ios::binary);
	std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	in.close();

	auto items = parse(bytes, error);
	CHECK(error.empty());
	CHECK(items.size() == originals.size());

	std::map<std::string, uint32_t> salts;
	for (const auto &it : items) {
		CHECK(originals.count(it.name) == 1);
		const auto &orig = originals[it.name];
		CHECK(it.size == orig.size());
		salts[it.name] = it.salt;

		// the stored bytes are encrypted (differ from the plaintext, for a non-empty file)
		std::vector<uint8_t> stored(bytes.begin() + it.start, bytes.begin() + it.start + it.size);
		if (it.size) CHECK(stored != orig);

		// decrypt the whole file (what the engine does for a single read from offset 0)
		std::vector<uint8_t> whole = stored;
		xorFile(whole.data(), whole.size(), 0, it.salt, key);
		CHECK(whole == orig);

		// decrypt in windows at arbitrary offsets (what the filter sees as the game seeks)
		for (auto win : std::vector<std::pair<size_t, size_t>>{ { 0, 1 }, { 1, 63 }, { 63, 200 }, { 64, 64 }, { 1000, 2000 } }) {
			const size_t off = win.first, len = win.second;
			if (off + len > it.size) continue;
			std::vector<uint8_t> part(stored.begin() + off, stored.begin() + off + len);
			xorFile(part.data(), part.size(), off, it.salt, key);
			CHECK(std::memcmp(part.data(), orig.data() + off, len) == 0);
		}
	}

	// every file got a distinct salt
	std::vector<uint32_t> all;
	for (auto &kv : salts) all.push_back(kv.second);
	std::sort(all.begin(), all.end());
	CHECK(std::unique(all.begin(), all.end()) == all.end());

	fs::remove_all(dir, ec);
	fs::remove(arc, ec);
	wipe(key);

	if (failures == 0) std::printf("xp3_test: all passed\n");
	return failures ? 1 : 0;
}

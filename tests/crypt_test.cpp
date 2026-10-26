// crypt_test.cpp - the cipher, the key format and the key slot. See xp3crypt.hpp.
//
// SPDX-License-Identifier: 0BSD

#include "xp3crypt.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace xp3crypt;

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

static Key testKey() {
	Key k;
	for (size_t i = 0; i < k.size(); i++) k[i] = uint8_t(i * 7 + 1);
	return k;
}

// Decrypting is the same as encrypting: xorFile twice gives back the original
static void roundTrip() {
	const Key key = testKey();
	for (size_t size : { size_t(0), size_t(1), size_t(63), size_t(64), size_t(65), size_t(1000), size_t(100000) }) {
		std::vector<uint8_t> plain(size), buf;
		for (size_t i = 0; i < size; i++) plain[i] = uint8_t(i * 31 + 5);
		buf = plain;
		xorFile(buf.data(), buf.size(), 0, 12345, key);
		if (size) CHECK(buf != plain);               // it actually changed the bytes
		xorFile(buf.data(), buf.size(), 0, 12345, key);
		CHECK(buf == plain);                          // and back
	}
}

// A read starting partway through a file decrypts the same as decrypting the whole file and
// taking that slice: the filter sees arbitrary offsets
static void seeking() {
	const Key key = testKey();
	const uint32_t salt = 0xABCDEF01;
	const size_t size = 5000;
	std::vector<uint8_t> plain(size);
	for (size_t i = 0; i < size; i++) plain[i] = uint8_t(i * 13 + 7);

	std::vector<uint8_t> whole = plain;
	xorFile(whole.data(), whole.size(), 0, salt, key);   // the stored (encrypted) file

	// decrypt a few windows at different offsets, including unaligned ones
	for (auto win : std::vector<std::pair<size_t, size_t>>{ { 0, 64 }, { 1, 64 }, { 63, 130 }, { 100, 1 }, { 4000, 1000 }, { 4999, 1 } }) {
		const size_t off = win.first, len = win.second;
		std::vector<uint8_t> part(whole.begin() + off, whole.begin() + off + len);
		xorFile(part.data(), part.size(), off, salt, key);
		CHECK(std::memcmp(part.data(), plain.data() + off, len) == 0);
	}
}

// Different salts (adlr numbers) give different keystreams, so identical plaintext encrypts
// differently per file
static void perFileKeystream() {
	const Key key = testKey();
	const size_t size = 256;
	std::vector<uint8_t> a(size, 0), b(size, 0);
	xorFile(a.data(), a.size(), 0, 1, key);
	xorFile(b.data(), b.size(), 0, 2, key);
	CHECK(a != b);
}

static void keyFormat() {
	Key k = testKey(), parsed;
	std::string error;
	const std::string hex = formatKey(k);
	CHECK(hex.size() == 64);
	CHECK(parseKey(hex, parsed, error));
	CHECK(parsed == k);
	CHECK(parseKey("  " + hex + "\n", parsed, error));   // surrounding whitespace ignored
	CHECK(!parseKey("too short", parsed, error));
	CHECK(!parseKey(std::string(64, '0'), parsed, error));   // all zero is rejected
	CHECK(!parseKey(std::string(63, 'a') + "g", parsed, error));   // non-hex
}

// A binary with the slot marker: findSlots finds it, writeSlots fills it, readSlot reads it back
static void slot() {
	const auto marker = slotMarker();
	std::vector<uint8_t> bin(200, 0x99);
	const size_t at = 40;
	std::memcpy(bin.data() + at, marker.data(), marker.size());
	// slot bytes (the key area) start all zero
	std::memset(bin.data() + at + SLOT_MARKER_SIZE, 0, KEY_SIZE);

	std::string error;
	auto slots = findSlots(bin.data(), bin.size(), error);
	CHECK(error.empty());
	CHECK(slots.size() == 1 && slots[0] == at);

	Key k = testKey(), got;
	CHECK(!readSlot(bin.data(), bin.size(), got, error));   // no key yet
	CHECK(error.empty());
	CHECK(writeSlots(bin, k, error) == 1);
	CHECK(readSlot(bin.data(), bin.size(), got, error));
	CHECK(got == k);

	std::vector<uint8_t> none(200, 0x99);
	CHECK(findSlots(none.data(), none.size(), error).empty());
	CHECK(error.empty());
	CHECK(writeSlots(none, k, error) == 0 && !error.empty());
}

int main() {
	roundTrip();
	seeking();
	perFileKeystream();
	keyFormat();
	slot();
	if (failures == 0) std::printf("crypt_test: all passed\n");
	return failures ? 1 : 0;
}

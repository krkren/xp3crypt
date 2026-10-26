// crypt.cpp - the cipher and the key format. The key-slot functions are in slot.cpp (kept out
// of the plugin), and this is compiled into both the plugin and the library. See xp3crypt.hpp.
//
// SPDX-License-Identifier: 0BSD

#include "xp3crypt.hpp"

#include "monocypher/monocypher.h"

#include <algorithm>
#include <cstring>

namespace xp3crypt {

namespace {

// The file's XChaCha20 key and nonce, from the game key and the file's adlr number
struct Subkeys {
	uint8_t key[32];
	uint8_t nonce[24];

	Subkeys(const Key &gameKey, uint32_t fileHash) {
		// context tag (12) + the number little-endian (4) = 16-byte message
		uint8_t msg[16] = { 'x', 'p', '3', 'c', 'r', 'y', 'p', 't', ' ', 'f', '1', 0,
			uint8_t(fileHash), uint8_t(fileHash >> 8), uint8_t(fileHash >> 16), uint8_t(fileHash >> 24) };
		uint8_t out[56];
		crypto_blake2b_keyed(out, sizeof(out), gameKey.data(), gameKey.size(), msg, sizeof(msg));
		std::memcpy(key, out, 32);
		std::memcpy(nonce, out + 32, 24);
		crypto_wipe(out, sizeof(out));
	}
	~Subkeys() {
		crypto_wipe(key, sizeof(key));
		crypto_wipe(nonce, sizeof(nonce));
	}
};

int hexDigit(char c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

} // namespace

void xorFile(uint8_t *buf, size_t size, uint64_t offset, uint32_t fileHash, const Key &key) {
	if (size == 0) return;
	Subkeys sub(key, fileHash);

	// XChaCha20 works in 64-byte blocks. When the read doesn't start on a block boundary, do the
	// rest of the first block from a one-block keystream, then the aligned remainder in place.
	uint64_t block = offset / 64;
	size_t within = size_t(offset % 64);
	size_t done = 0;
	if (within) {
		uint8_t ks[64] = { 0 };
		crypto_chacha20_x(ks, ks, 64, sub.key, sub.nonce, block);   // plaintext 0 -> ks = keystream
		size_t take = std::min<size_t>(64 - within, size);
		for (size_t i = 0; i < take; i++) buf[i] = uint8_t(buf[i] ^ ks[within + i]);
		crypto_wipe(ks, sizeof(ks));
		done = take;
		block++;
	}
	if (done < size) {
		crypto_chacha20_x(buf + done, buf + done, size - done, sub.key, sub.nonce, block);
	}
}

bool parseKey(const std::string &text, Key &key, std::string &error) {
	size_t a = 0, b = text.size();
	while (a < b && (text[a] == ' ' || text[a] == '\t' || text[a] == '\r' || text[a] == '\n')) a++;
	while (b > a && (text[b - 1] == ' ' || text[b - 1] == '\t' || text[b - 1] == '\r' || text[b - 1] == '\n')) b--;
	if (b - a != 64) { error = "a key is 64 hexadecimal digits"; return false; }
	bool any = false;
	for (size_t k = 0; k < 32; k++) {
		int hi = hexDigit(text[a + 2 * k]), lo = hexDigit(text[a + 2 * k + 1]);
		if (hi < 0 || lo < 0) { error = "a key is 64 hexadecimal digits"; return false; }
		key[k] = uint8_t(hi * 16 + lo);
		any = any || key[k] != 0;
	}
	if (!any) { error = "a key of all zeros means no key"; return false; }
	return true;
}

std::string formatKey(const Key &key) {
	static const char *digits = "0123456789abcdef";
	std::string s;
	for (uint8_t b : key) {
		s.push_back(digits[b >> 4]);
		s.push_back(digits[b & 15]);
	}
	return s;
}

void wipe(Key &key) {
	crypto_wipe(key.data(), key.size());
}

} // namespace xp3crypt

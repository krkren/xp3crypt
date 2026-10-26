// crypt_random.cpp - a fresh key from the operating system's random source. Kept apart from
// crypt.cpp so the plugin, which never makes keys, leaves it out.
//
// SPDX-License-Identifier: 0BSD

#include "xp3crypt.hpp"

#include <stdexcept>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <cstdio>
#if defined(__linux__)
#include <sys/random.h>
#endif
#endif

namespace xp3crypt {

Key randomKey() {
	Key key{};
#if defined(_WIN32)
	if (BCryptGenRandom(nullptr, key.data(), (ULONG)key.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
		throw std::runtime_error("the system's random source (BCryptGenRandom) failed");
#else
#if defined(__linux__)
	size_t got = 0;
	while (got < key.size()) {
		ssize_t n = getrandom(key.data() + got, key.size() - got, 0);
		if (n < 0) { got = 0; break; }   // fall through to /dev/urandom
		got += size_t(n);
	}
	if (got == key.size()) return key;
#endif
	FILE *f = std::fopen("/dev/urandom", "rb");
	if (!f) throw std::runtime_error("the system's random source (/dev/urandom) can't be opened");
	const size_t n = std::fread(key.data(), 1, key.size(), f);
	std::fclose(f);
	if (n != key.size()) throw std::runtime_error("the system's random source gave too few bytes");
#endif
	return key;
}

} // namespace xp3crypt

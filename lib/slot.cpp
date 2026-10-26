// slot.cpp - the key slot inside a binary: finding it, reading it, writing a key into it. This
// is the packaging side (the CLI and a game's build tool); the plugin never calls these, so it
// isn't compiled into the plugin. (That matters: the compiler constant-folds slotMarker() back
// into a plain copy of the marker, so a plugin that compiled this would carry a second marker
// and the packer couldn't tell which one is the real slot.) See xp3crypt.hpp.
//
// SPDX-License-Identifier: 0BSD

#include "xp3crypt.hpp"

#include <cstring>

namespace xp3crypt {

namespace {

// "XP3CRYPT-KEYSLOT", each byte inverted, so the source holds no plain copy of the marker
const uint8_t MARKER_INVERTED[SLOT_MARKER_SIZE] = {
	0xA7, 0xAF, 0xCC, 0xBC, 0xAD, 0xA6, 0xAF, 0xAB, 0xD2, 0xB4, 0xBA, 0xA6, 0xAC, 0xB3, 0xB0, 0xAB,
};

} // namespace

std::array<uint8_t, SLOT_MARKER_SIZE> slotMarker() {
	std::array<uint8_t, SLOT_MARKER_SIZE> m;
	for (size_t k = 0; k < SLOT_MARKER_SIZE; k++) m[k] = uint8_t(~MARKER_INVERTED[k]);
	return m;
}

std::vector<size_t> findSlots(const uint8_t *data, size_t size, std::string &error) {
	error.clear();
	const auto m = slotMarker();
	std::vector<size_t> at;
	if (size >= SLOT_SIZE) {
		for (size_t k = 0; k + SLOT_MARKER_SIZE <= size; k++) {
			if (data[k] == m[0] && std::memcmp(data + k, m.data(), SLOT_MARKER_SIZE) == 0) {
				if (k + SLOT_SIZE > size) { error = "a key slot is cut short"; return {}; }
				at.push_back(k);
			}
		}
	}
	if (at.size() > 1) {
		// a universal (fat) Mach-O holds one slot per architecture; otherwise there's one
		const bool fat = size >= 8 && data[0] == 0xca && data[1] == 0xfe && data[2] == 0xba &&
		                 (data[3] == 0xbe || data[3] == 0xbf);
		const uint32_t arches = fat ? uint32_t(data[4] << 24 | data[5] << 16 | data[6] << 8 | data[7]) : 1;
		if (at.size() > arches) { error = "more key slots than the binary should have"; return {}; }
	}
	return at;
}

bool readSlot(const uint8_t *data, size_t size, Key &key, std::string &error) {
	const auto at = findSlots(data, size, error);
	if (!error.empty() || at.empty()) return false;
	bool any = false;
	for (size_t k = 0; k < 32; k++) {
		key[k] = data[at[0] + SLOT_MARKER_SIZE + k];
		any = any || key[k] != 0;
	}
	return any;
}

int writeSlots(std::vector<uint8_t> &binary, const Key &key, std::string &error) {
	const auto at = findSlots(binary.data(), binary.size(), error);
	if (!error.empty()) return 0;
	if (at.empty()) { error = "no key slot (is this the xp3crypt plugin, or an engine with it built in?)"; return 0; }
	for (size_t off : at) std::memcpy(&binary[off + SLOT_MARKER_SIZE], key.data(), key.size());
	return int(at.size());
}

} // namespace xp3crypt

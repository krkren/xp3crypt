// main.cpp - the xp3crypt plugin. It installs an XP3 archive extraction filter that decrypts
// each read with the game's key, so an encrypted data.xp3 is read transparently.
//
// The plugin is meant to be linked into the engine executable (krkrz_dev's TVP_PLUGINS_STATIC),
// so its filter is in place before the engine reads startup.tjs. It also builds as a normal
// shared plugin for desktop testing, where a script links it before the game window is made.
//
// The game's key lives in xp3crypt_key_slot below; a game's packaging tool (the xp3crypt CLI,
// or kagex-release) writes the key into that slot in the shipped binary. Until then the slot is
// all zero and the filter passes every read through untouched, so an engine with the plugin but
// no key still runs a plain archive.
//
// It also exposes a small TJS class for diagnostics:
//   XP3Crypt.hasKey   -> whether a key has been written into this build
//
// SPDX-License-Identifier: 0BSD

#include "ncbind.hpp"
#include "xp3crypt.hpp"

// The key slot: a 16-byte marker then 32 key bytes, all zero until a game's key is written in.
// volatile and "used" so the compiler keeps it and always reads the bytes that are in the file;
// not const, so the slot sits in a writable data section the packer can patch.
extern "C" {
#if defined(__GNUC__) || defined(__clang__)
__attribute__((used))
#endif
volatile unsigned char xp3crypt_key_slot[xp3crypt::SLOT_SIZE] = {
	'X', 'P', '3', 'C', 'R', 'Y', 'P', 'T', '-', 'K', 'E', 'Y', 'S', 'L', 'O', 'T',
};
}

namespace {

// The key in the slot; false (and key wiped) when the slot is all zero
bool slotKey(xp3crypt::Key &key) {
	bool any = false;
	for (size_t k = 0; k < key.size(); k++) {
		key[k] = xp3crypt_key_slot[xp3crypt::SLOT_MARKER_SIZE + k];
		any = any || key[k] != 0;
	}
	if (!any) xp3crypt::wipe(key);
	return any;
}

// The extraction filter: the engine calls this for every archive read, with the file's bytes at
// info->Offset and the file's adlr number in info->FileHash. We decrypt in place.
void TVP_tTVPXP3ArchiveExtractionFilter_CONVENTION xp3cryptFilter(tTVPXP3ExtractionFilterInfo *info) {
	if (!info || !info->Buffer || info->BufferSize == 0) return;
	xp3crypt::Key key;
	if (!slotKey(key)) return;   // no key: leave the data as it is
	xp3crypt::xorFile(reinterpret_cast<uint8_t *>(info->Buffer), info->BufferSize, info->Offset, info->FileHash, key);
	xp3crypt::wipe(key);
}

bool filterInstalled = false;

void installFilter() {
	TVPSetXP3ArchiveExtractionFilter(xp3cryptFilter);
	filterInstalled = true;
}

void removeFilter() {
	TVPSetXP3ArchiveExtractionFilter(nullptr);
	filterInstalled = false;
}

} // namespace

// Diagnostics for scripts and the smoke test
class XP3Crypt {
public:
	static bool hasKey() {
		xp3crypt::Key key;
		bool any = slotKey(key);
		xp3crypt::wipe(key);
		return any;
	}
	static bool installed() { return filterInstalled; }
};

NCB_REGISTER_CLASS(XP3Crypt) {
	Property(TJS_W("hasKey"), &Class::hasKey, (int)0);
	Property(TJS_W("installed"), &Class::installed, (int)0);
}

// Install the filter when the plugin links (before startup.tjs for a built-in plugin), and take
// it off when it unlinks.
NCB_POST_REGIST_CALLBACK(installFilter);
NCB_PRE_UNREGIST_CALLBACK(removeFilter);

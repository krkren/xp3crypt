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
// It also serves an archive whose file names are hashed, through a storage medium (xpcrypt://,
// as minizip serves zip://): the engine's built-in XP3 mount matches plain names, so to hide
// the names we do the lookup ourselves — each request is keyed-hashed and matched against the
// hashes in the index, and the file's bytes are decrypted on read. Like the engine's XP3 reader,
// it lists and matches names in lower case (ASCII).
//
// It also exposes a small TJS class:
//   XP3Crypt.hasKey                      -> whether a key has been written into this build
//   XP3Crypt.mount(domain, archive)      -> mount a hashed archive as xpcrypt://<domain>/
//   XP3Crypt.unmount(domain)
//
// SPDX-License-Identifier: 0BSD

#include "ncbind.hpp"
#include "xp3crypt.hpp"

#include <map>
#include <string>
#include <vector>

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

// ------------------------------------------------------------------------
// The hashed-name archive, served as a storage medium (xpcrypt://)
// ------------------------------------------------------------------------

// TJS strings are UTF-16; a path to hash is UTF-8
std::string toUtf8(const tjs_char *s, size_t len) {
	std::string out;
	out.reserve(len);
	for (size_t k = 0; k < len; k++) {
		uint32_t c = uint16_t(s[k]);
		if (c >= 0xD800 && c < 0xDC00 && k + 1 < len && uint16_t(s[k + 1]) >= 0xDC00 && uint16_t(s[k + 1]) < 0xE000) {
			c = 0x10000 + ((c - 0xD800) << 10) + (uint16_t(s[k + 1]) - 0xDC00);
			k++;
		} else if (c >= 0xD800 && c < 0xE000) {
			c = 0xFFFD;
		}
		if (c < 0x80) out.push_back(char(c));
		else if (c < 0x800) { out.push_back(char(0xC0 | (c >> 6))); out.push_back(char(0x80 | (c & 0x3F))); }
		else if (c < 0x10000) { out.push_back(char(0xE0 | (c >> 12))); out.push_back(char(0x80 | ((c >> 6) & 0x3F))); out.push_back(char(0x80 | (c & 0x3F))); }
		else { out.push_back(char(0xF0 | (c >> 18))); out.push_back(char(0x80 | ((c >> 12) & 0x3F))); out.push_back(char(0x80 | ((c >> 6) & 0x3F))); out.push_back(char(0x80 | (c & 0x3F))); }
	}
	return out;
}
std::string toUtf8(const ttstr &s) { return toUtf8(s.c_str(), size_t(s.GetLen())); }

ttstr fromUtf8(const std::string &s) {
	std::vector<tjs_char> out;
	out.reserve(s.size() + 1);
	const unsigned char *p = reinterpret_cast<const unsigned char *>(s.data());
	const size_t n = s.size();
	for (size_t k = 0; k < n;) {
		uint32_t c = p[k];
		int extra = c < 0x80 ? 0 : (c >> 5) == 6 ? 1 : (c >> 4) == 14 ? 2 : (c >> 3) == 30 ? 3 : -1;
		if (extra < 0 || k + size_t(extra) >= n) { out.push_back(0xFFFD); k++; continue; }
		c = extra == 0 ? c : extra == 1 ? (c & 0x1F) : extra == 2 ? (c & 0x0F) : (c & 0x07);
		for (int e = 1; e <= extra; e++) c = (c << 6) | (p[k + e] & 0x3F);
		k += size_t(extra) + 1;
		if (c >= 0x10000) { c -= 0x10000; out.push_back(tjs_char(0xD800 + (c >> 10))); out.push_back(tjs_char(0xDC00 + (c & 0x3FF))); }
		else out.push_back(tjs_char(c));
	}
	out.push_back(0);
	return ttstr(out.data());
}

// A read-only stream over one encrypted file in the archive, decrypting on read
class DecryptStream : public iTJSBinaryStream {
public:
	DecryptStream(iTJSBinaryStream *arc, uint64_t base, uint64_t size, uint32_t salt, const xp3crypt::Key &key)
		: arc_(arc), base_(base), size_(size), salt_(salt), key_(key) {}
	~DecryptStream() override {
		if (arc_) arc_->Destruct();
		xp3crypt::wipe(key_);
	}
	tjs_uint64 TJS_INTF_METHOD Seek(tjs_int64 offset, tjs_int whence) override {
		tjs_int64 np = whence == TJS_BS_SEEK_SET ? offset : whence == TJS_BS_SEEK_CUR ? tjs_int64(pos_) + offset : tjs_int64(size_) + offset;
		if (np < 0) np = 0;
		if (np > tjs_int64(size_)) np = tjs_int64(size_);
		pos_ = tjs_uint64(np);
		return pos_;
	}
	tjs_uint TJS_INTF_METHOD Read(void *buffer, tjs_uint readSize) override {
		if (pos_ >= size_) return 0;
		const tjs_uint64 avail = size_ - pos_;
		tjs_uint want = readSize > avail ? tjs_uint(avail) : readSize;
		arc_->Seek(tjs_int64(base_ + pos_), TJS_BS_SEEK_SET);
		tjs_uint got = 0;
		while (got < want) {
			const tjs_uint n = arc_->Read(reinterpret_cast<tjs_uint8 *>(buffer) + got, want - got);
			if (n == 0) break;
			got += n;
		}
		xp3crypt::xorFile(reinterpret_cast<uint8_t *>(buffer), got, pos_, salt_, key_);
		pos_ += got;
		return got;
	}
	tjs_uint TJS_INTF_METHOD Write(const void *, tjs_uint) override { return 0; }
	void TJS_INTF_METHOD SetEndOfStorage() override { TVPThrowExceptionMessage(TJS_W("xpcrypt:// is read-only")); }
	tjs_uint64 TJS_INTF_METHOD GetSize() override { return size_; }

private:
	iTJSBinaryStream *arc_;
	uint64_t base_, size_, pos_ = 0;
	uint32_t salt_;
	xp3crypt::Key key_;
};

struct Blob {
	uint64_t offset, size;
	uint32_t salt;
};

struct Mount {
	ttstr archive;                                      // the archive's storage name
	std::map<std::string, Blob> byHash;                 // stored name (the hash) -> its bytes
	std::map<std::string, std::vector<std::string>> listing;   // folder -> leaf names, all lower case (manifestFolders)
	xp3crypt::Key key;
	~Mount() { xp3crypt::wipe(key); }
};

class Xp3cStorage : public iTVPStorageMedia {
public:
	~Xp3cStorage() { for (auto &m : mounts_) delete m.second; }

	void TJS_INTF_METHOD AddRef() override { ref_++; }
	void TJS_INTF_METHOD Release() override { if (ref_ == 1) delete this; else ref_--; }
	void TJS_INTF_METHOD GetName(ttstr &name) override { name = TJS_W("xpcrypt"); }
	void TJS_INTF_METHOD NormalizeDomainName(ttstr &) override {}
	// Paths are lower case (ASCII), as the engine makes an archive's in-archive names: the
	// engine picks a decoder by a name's extension as spelt, and the hash folds case anyway
	void TJS_INTF_METHOD NormalizePathName(ttstr &name) override {
		if (name.IsEmpty()) return;
		for (tjs_char *p = name.Independ(); *p; p++) if (*p >= TJS_W('A') && *p <= TJS_W('Z')) *p += TJS_W('a') - TJS_W('A');
	}
	void TJS_INTF_METHOD GetListAt(const ttstr &name, iTVPStorageLister *lister) override {
		if (!lister) return;
		// name is "domain/folder"; list the manifest's leaves directly under that folder
		const tjs_char *p = name.c_str();
		const tjs_char *q = nullptr;
		for (const tjs_char *r = p; *r; r++) if (*r == TJS_W('/')) { q = r; break; }
		const ttstr domain = q ? ttstr(p, int(q - p)) : name;
		const auto it = mounts_.find(domain);
		if (it == mounts_.end()) return;
		std::string folder = q ? toUtf8(q + 1) : std::string();
		while (!folder.empty() && folder.back() == '/') folder.pop_back();
		for (char &c : folder) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
		const auto f = it->second->listing.find(folder);
		if (f == it->second->listing.end()) return;
		for (const std::string &leaf : f->second) lister->Add(fromUtf8(leaf));
	}
	void TJS_INTF_METHOD GetLocallyAccessibleName(ttstr &name) override { name = TJS_W(""); }

	bool TJS_INTF_METHOD CheckExistentStorage(const ttstr &name) override {
		const Mount *m = find(name);
		return m != nullptr;
	}

	iTJSBinaryStream *TJS_INTF_METHOD Open(const ttstr &name, tjs_uint32 flags) override {
		if (flags == TJS_BS_READ) {
			std::string hash;
			const Mount *m = find(name, &hash);
			if (m) {
				const auto it = m->byHash.find(hash);
				if (it != m->byHash.end()) {
					iTJSBinaryStream *arc = TVPCreateStream(m->archive, TJS_BS_READ);
					if (arc) return new DecryptStream(arc, it->second.offset, it->second.size, it->second.salt, m->key);
				}
			}
		}
		TVPThrowExceptionMessage(TJS_W("xpcrypt: can't open %1"), name);
		return nullptr;
	}

	bool mount(const ttstr &domain, const ttstr &archive) {
		unmount(domain);
		xp3crypt::Key key;
		if (!slotKey(key)) { xp3crypt::wipe(key); return false; }   // no key: nothing to serve
		iTJSBinaryStream *s = TVPCreateStream(archive, TJS_BS_READ);
		if (!s) { xp3crypt::wipe(key); return false; }
		std::vector<xp3crypt::IndexEntry> entries;
		std::string err;
		const tjs_uint64 size = s->GetSize();
		const bool ok = xp3crypt::readIndex(
			[s](uint64_t off, void *buf, size_t len) {
				s->Seek(tjs_int64(off), TJS_BS_SEEK_SET);
				tjs_uint got = 0;
				while (got < len) {
					const tjs_uint n = s->Read(reinterpret_cast<tjs_uint8 *>(buf) + got, tjs_uint(len - got));
					if (n == 0) break;
					got += n;
				}
			},
			size, entries, err);
		s->Destruct();
		if (!ok) { xp3crypt::wipe(key); return false; }
		Mount *m = new Mount();
		m->archive = archive;
		m->key = key;
		for (const auto &e : entries) m->byHash[e.name] = { e.offset, e.size, e.fileHash };

		// decrypt the name manifest and build the folder listing for GetListAt
		const std::string manifestHash = xp3crypt::manifestName(key);
		const auto mit = m->byHash.find(manifestHash);
		if (mit != m->byHash.end()) {
			iTJSBinaryStream *ms = TVPCreateStream(archive, TJS_BS_READ);
			if (ms) {
				std::vector<uint8_t> data(size_t(mit->second.size));
				ms->Seek(tjs_int64(mit->second.offset), TJS_BS_SEEK_SET);
				tjs_uint got = 0;
				while (got < data.size()) {
					const tjs_uint n = ms->Read(data.data() + got, tjs_uint(data.size() - got));
					if (n == 0) break;
					got += n;
				}
				ms->Destruct();
				if (!data.empty()) xp3crypt::xorFile(data.data(), data.size(), 0, mit->second.salt, key);
				m->listing = xp3crypt::manifestFolders(std::string(data.begin(), data.end()));
			}
		}
		xp3crypt::wipe(key);
		mounts_[domain] = m;
		return true;
	}

	bool unmount(const ttstr &domain) {
		const auto it = mounts_.find(domain);
		if (it == mounts_.end()) return false;
		delete it->second;
		mounts_.erase(it);
		return true;
	}

private:
	// name is "domain/path"; returns the mount and (when wanted) the path's hash
	const Mount *find(const ttstr &name, std::string *outHash = nullptr) {
		const tjs_char *p = name.c_str();
		const tjs_char *q = nullptr;
		for (const tjs_char *r = p; *r; r++) if (*r == TJS_W('/')) { q = r; break; }
		if (!q) return nullptr;
		const ttstr domain(p, int(q - p));
		const auto it = mounts_.find(domain);
		if (it == mounts_.end()) return nullptr;
		const std::string hash = xp3crypt::hashName(it->second->key, toUtf8(q + 1));
		if (!it->second->byHash.count(hash)) return nullptr;
		if (outHash) *outHash = hash;
		return it->second;
	}

	tjs_uint ref_ = 1;
	std::map<ttstr, Mount *> mounts_;
};

Xp3cStorage *g_media = nullptr;

void registerMedia() {
	if (!g_media) {
		g_media = new Xp3cStorage();
		TVPRegisterStorageMedia(g_media);
	}
}
void unregisterMedia() {
	if (g_media) {
		TVPUnregisterStorageMedia(g_media);
		g_media->Release();
		g_media = nullptr;
	}
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

	// XP3Crypt.mount(domain, archive): serve a hashed archive as xpcrypt://<domain>/. Returns true
	// when mounted (false when there's no key or the archive can't be read)
	static tjs_error TJS_INTF_METHOD mount(tTJSVariant *result, tjs_int numparams, tTJSVariant **param, iTJSDispatch2 *) {
		if (numparams < 2) return TJS_E_BADPARAMCOUNT;
		const bool ok = g_media && g_media->mount(ttstr(*param[0]), ttstr(*param[1]));
		if (result) *result = (tjs_int)(ok ? 1 : 0);
		return TJS_S_OK;
	}
	// XP3Crypt.unmount(domain)
	static tjs_error TJS_INTF_METHOD unmount(tTJSVariant *result, tjs_int numparams, tTJSVariant **param, iTJSDispatch2 *) {
		if (numparams < 1) return TJS_E_BADPARAMCOUNT;
		const bool ok = g_media && g_media->unmount(ttstr(*param[0]));
		if (result) *result = (tjs_int)(ok ? 1 : 0);
		return TJS_S_OK;
	}
};

NCB_REGISTER_CLASS(XP3Crypt) {
	Property(TJS_W("hasKey"), &Class::hasKey, (int)0);
	Property(TJS_W("installed"), &Class::installed, (int)0);
	RawCallback(TJS_W("mount"), &Class::mount, TJS_STATICMEMBER);
	RawCallback(TJS_W("unmount"), &Class::unmount, TJS_STATICMEMBER);
}

void linkPlugin() {
	installFilter();
	registerMedia();
}
void unlinkPlugin() {
	unregisterMedia();
	removeFilter();
}

// Install the filter and the xpcrypt:// medium when the plugin links (before startup.tjs for a
// built-in plugin), and take them off when it unlinks.
NCB_POST_REGIST_CALLBACK(linkPlugin);
NCB_PRE_UNREGIST_CALLBACK(unlinkPlugin);

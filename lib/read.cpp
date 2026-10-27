// read.cpp - parsing an XP3 archive's index and a hashed archive's name manifest (the storage
// medium and the tests use them). No file system, and no zlib unless the archive's index is
// compressed (hashed archives are packed with an uncompressed index, so the plugin needs no
// zlib). See xp3crypt.hpp.
//
// SPDX-License-Identifier: 0BSD

#include "xp3crypt.hpp"

#include <cstring>

#ifdef XP3CRYPT_HAVE_ZLIB
#include <zlib.h>
#endif

namespace xp3crypt {

namespace {

uint16_t rd16(const uint8_t *p) { return uint16_t(p[0] | (p[1] << 8)); }
uint32_t rd32(const uint8_t *p) { return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24); }
uint64_t rd64(const uint8_t *p) { return uint64_t(rd32(p)) | (uint64_t(rd32(p + 4)) << 32); }

// A chunk named `name` within [from, to) of the index
bool findChunk(const std::vector<uint8_t> &d, size_t from, size_t to, const char *name, size_t &start, size_t &size) {
	size_t pos = from;
	while (pos + 12 <= to) {
		const uint64_t sz = rd64(&d[pos + 4]);
		if (pos + 12 + sz > to) return false;
		if (std::memcmp(&d[pos], name, 4) == 0) { start = pos + 12; size = size_t(sz); return true; }
		pos += 12 + size_t(sz);
	}
	return false;
}

// An index name (UTF-16) as UTF-8; an unpaired surrogate becomes U+FFFD
std::string utf16ToUtf8(const std::vector<uint16_t> &s) {
	std::string out;
	for (size_t k = 0; k < s.size(); k++) {
		uint32_t c = s[k];
		if (c >= 0xD800 && c < 0xDC00 && k + 1 < s.size() && s[k + 1] >= 0xDC00 && s[k + 1] < 0xE000) {
			c = 0x10000 + ((c - 0xD800) << 10) + (s[k + 1] - 0xDC00);
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

void lowerAscii(std::string &s) {
	for (char &c : s) if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
}

} // namespace

std::map<std::string, std::vector<std::string>> manifestFolders(const std::string &manifest) {
	std::map<std::string, std::vector<std::string>> folders;
	auto take = [&](std::string path) {
		if (path.empty()) return;
		lowerAscii(path);
		const size_t slash = path.find_last_of('/');
		if (slash == std::string::npos) folders[std::string()].push_back(path);
		else folders[path.substr(0, slash)].push_back(path.substr(slash + 1));
	};
	size_t from = 0;
	for (size_t nl; (nl = manifest.find('\n', from)) != std::string::npos; from = nl + 1) take(manifest.substr(from, nl - from));
	take(manifest.substr(from));
	return folders;
}

bool readIndex(const Reader &read, uint64_t size, std::vector<IndexEntry> &out, std::string &error) {
	out.clear();
	auto at64 = [&](uint64_t off) -> uint64_t {
		uint8_t b[8];
		read(off, b, 8);
		return rd64(b);
	};
	if (size < 19) { error = "the archive is too small"; return false; }
	{
		uint8_t magic[4];
		read(0, magic, 4);
		if (magic[0] != 'X' || magic[1] != 'P' || magic[2] != '3') { error = "not an XP3 archive"; return false; }
	}

	// follow the index chain (the cushion header, then the real index)
	std::vector<uint8_t> index;
	uint64_t pos = 11;
	for (int guard = 0; guard < 32; guard++) {
		if (pos + 8 > size) { error = "the index pointer is out of range"; return false; }
		const uint64_t ofs = at64(pos);
		if (ofs + 1 > size) { error = "the index is out of range"; return false; }
		uint8_t flag;
		read(ofs, &flag, 1);
		uint64_t p = ofs + 1;
		if ((flag & 0x07) == 0) {   // raw
			const uint64_t isz = at64(p);
			p += 8;
			if (p + isz > size) { error = "the index is out of range"; return false; }
			const size_t before = index.size();
			index.resize(before + size_t(isz));
			if (isz) read(p, index.data() + before, size_t(isz));
			p += isz;
		} else if ((flag & 0x07) == 1) {   // zlib
#ifdef XP3CRYPT_HAVE_ZLIB
			const uint64_t clen = at64(p);
			p += 8;
			const uint64_t olen = at64(p);
			p += 8;
			if (p + clen > size) { error = "the index is out of range"; return false; }
			std::vector<uint8_t> comp(size_t(clen));
			if (clen) read(p, comp.data(), size_t(clen));
			p += clen;
			const size_t before = index.size();
			index.resize(before + size_t(olen));
			uLongf got = uLongf(olen);
			if (uncompress(index.data() + before, &got, comp.data(), uLong(clen)) != Z_OK || got != olen) {
				error = "the index's zlib data is corrupt";
				return false;
			}
#else
			error = "the archive has a compressed index, which this build can't read";
			return false;
#endif
		} else {
			error = "the index has an unknown encoding";
			return false;
		}
		if (flag & 0x80) { pos = p; continue; }   // continue: the next pointer is right after
		break;
	}

	// walk the File chunks
	size_t fstart = 0, fsize = 0, cs = 0, csz = 0, scan = 0;
	while (findChunk(index, scan, index.size(), "File", fstart, fsize)) {
		const size_t fend = fstart + fsize;
		IndexEntry e;
		if (!findChunk(index, fstart, fend, "info", cs, csz) || csz < 22) { error = "a File has no info"; return false; }
		const uint16_t namelen = rd16(&index[cs + 20]);
		if (cs + 22 + size_t(namelen) * 2 > fend) { error = "a File's name is out of range"; return false; }
		std::vector<uint16_t> n16(namelen);
		for (uint16_t i = 0; i < namelen; i++) n16[i] = rd16(&index[cs + 22 + i * 2]);
		e.name = utf16ToUtf8(n16);
		if (!findChunk(index, fstart, fend, "segm", cs, csz) || csz < 28) { error = "a File has no segm"; return false; }
		e.offset = rd64(&index[cs + 4]);
		e.size = rd64(&index[cs + 12]);
		if (findChunk(index, fstart, fend, "adlr", cs, csz) && csz >= 4) e.fileHash = rd32(&index[cs]);
		out.push_back(std::move(e));
		scan = fend;
	}
	return true;
}

} // namespace xp3crypt

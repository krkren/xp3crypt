// xp3.cpp - packing a folder into an encrypted XP3 archive. The byte layout matches the SDL3
// engine's reader (common/base/XP3Archive.cpp) and the Kirikiri 2 releaser's "cushion" header,
// as krkrz_tools' own writer produces it; every file is stored uncompressed and encrypted, with
// a unique number in its adlr chunk that the engine passes to the plugin as the file's key salt.
//
// SPDX-License-Identifier: 0BSD

#include "xp3crypt.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>

#ifdef XP3CRYPT_HAVE_ZLIB
#include <zlib.h>
#endif

namespace fs = std::filesystem;

namespace xp3crypt {

namespace {

const unsigned char MARK1[8] = { 'X', 'P', '3', 0x0d, 0x0a, 0x20, 0x0a, 0x1a };
const unsigned char MARK2[3] = { 0x8b, 0x67, 0x01 };

void put16(std::string &s, uint16_t v) { s += char(v & 0xff); s += char(v >> 8); }
void put32(std::string &s, uint32_t v) { for (int i = 0; i < 4; i++) s += char((v >> (8 * i)) & 0xff); }
void put64(std::string &s, uint64_t v) { for (int i = 0; i < 8; i++) s += char((v >> (8 * i)) & 0xff); }

std::u16string utf8ToUtf16(const std::string &s) {
	std::u16string out;
	for (size_t i = 0; i < s.size();) {
		unsigned char c = (unsigned char)s[i];
		uint32_t cp;
		int n;
		if (c < 0x80) { cp = c; n = 0; }
		else if ((c >> 5) == 6) { cp = c & 0x1f; n = 1; }
		else if ((c >> 4) == 14) { cp = c & 0x0f; n = 2; }
		else { cp = c & 0x07; n = 3; }
		for (int k = 1; k <= n && i + k < s.size(); k++) cp = (cp << 6) | ((unsigned char)s[i + k] & 0x3f);
		i += n + 1;
		if (cp >= 0x10000) {
			cp -= 0x10000;
			out += char16_t(0xd800 + (cp >> 10));
			out += char16_t(0xdc00 + (cp & 0x3ff));
		} else {
			out += char16_t(cp);
		}
	}
	return out;
}

std::string lowerExt(const fs::path &p) {
	std::string e = p.extension().string();
	for (char &c : e) c = char(std::tolower((unsigned char)c));
	return e;
}

} // namespace

bool pack(const fs::path &sourceDir, const fs::path &output, const Key &key, const PackOptions &opt,
          PackResult &result, std::string &error, const Progress &progress) {
	result = PackResult{};
	std::error_code ec;

	// collect the files (skip names starting with '.' and CVS folders, and the output itself)
	struct Src { fs::path path; std::string name; uint64_t size; };
	std::vector<Src> files;
	const fs::path outAbs = fs::weakly_canonical(output, ec);
	auto it = fs::recursive_directory_iterator(sourceDir, fs::directory_options::skip_permission_denied, ec);
	if (ec) { error = "can't open the folder " + sourceDir.string(); return false; }
	for (; it != fs::recursive_directory_iterator(); it.increment(ec)) {
		if (ec) { error = "can't read the folder: " + ec.message(); return false; }
		const std::string fname = it->path().filename().string();
		if (it->is_directory(ec)) {
			if ((!fname.empty() && fname[0] == '.') || fname == "CVS") it.disable_recursion_pending();
			continue;
		}
		if (!it->is_regular_file(ec)) continue;
		if (!fname.empty() && fname[0] == '.') continue;
		if (fs::weakly_canonical(it->path(), ec) == outAbs) continue;
		if (opt.discard.count(lowerExt(it->path()))) continue;
		std::string name = fs::relative(it->path(), sourceDir, ec).generic_string();
		files.push_back({ it->path(), name, uint64_t(it->file_size(ec)) });
	}
	std::sort(files.begin(), files.end(), [](const Src &a, const Src &b) { return a.name < b.name; });

	std::ofstream out(output, std::ios::binary | std::ios::trunc);
	if (!out) { error = "can't create " + output.string(); return false; }
	auto write = [&](const void *p, size_t n) { out.write(reinterpret_cast<const char *>(p), std::streamsize(n)); };

	// header (cushion form): offset 11 -> 0x17, which holds an empty "continue" index, then the
	// real index pointer at offset 32
	{
		std::string h(reinterpret_cast<const char *>(MARK1), 8);
		h.append(reinterpret_cast<const char *>(MARK2), 3);
		put64(h, 11 + 4 + 8);   // 0x17
		put32(h, 1);            // header version
		h += char(0x80);        // continue
		put64(h, 0);            // an index of size 0
		write(h.data(), h.size());
	}
	const uint64_t indexPointerPos = 32;
	write("\0\0\0\0\0\0\0\0", 8);   // real index position, filled in at the end

	struct Packed { std::string name; uint32_t salt; uint64_t start; uint64_t size; };
	std::vector<Packed> packed;

	uint64_t total = 0, done = 0;
	for (const auto &f : files) total += std::max<uint64_t>(f.size, 1);
	uint32_t salt = 0;
	std::vector<uint8_t> buf;

	for (const auto &f : files) {
		if (progress && !progress(f.name, done, total)) { result.canceled = true; error = "canceled"; return false; }
		std::ifstream in(f.path, std::ios::binary);
		if (!in) { error = "can't open " + f.name; return false; }
		buf.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());

		++salt;   // a unique, non-zero number per file; the engine hands it back as the salt
		const uint64_t start = uint64_t(out.tellp());
		if (!buf.empty()) {
			xorFile(buf.data(), buf.size(), 0, salt, key);
			write(buf.data(), buf.size());
		}
		packed.push_back({ f.name, salt, start, uint64_t(buf.size()) });
		result.orgBytes += f.size;
		++result.files;
		done += std::max<uint64_t>(f.size, 1);
	}

	// the index: one "File" chunk per file (info, segm, adlr)
	std::string index;
	for (const auto &p : packed) {
		const std::u16string n16 = utf8ToUtf16(p.name);
		std::string info;
		put32(info, 0);            // flags (not the protect bit: the engine refuses those at load)
		put64(info, p.size);       // original size
		put64(info, p.size);       // stored size (uncompressed)
		put16(info, uint16_t(n16.size()));
		for (char16_t c : n16) put16(info, uint16_t(c));
		std::string segm;
		put32(segm, 0);            // one raw (uncompressed) segment
		put64(segm, p.start);
		put64(segm, p.size);
		put64(segm, p.size);
		std::string adlr;
		put32(adlr, p.salt);
		std::string body;
		body += "info"; put64(body, info.size()); body += info;
		body += "segm"; put64(body, segm.size()); body += segm;
		body += "adlr"; put64(body, adlr.size()); body += adlr;
		index += "File"; put64(index, body.size()); index += body;
	}

	const uint64_t indexPos = uint64_t(out.tellp());
	bool wroteCompressed = false;
#ifdef XP3CRYPT_HAVE_ZLIB
	if (opt.compressIndex && !index.empty()) {
		uLongf clen = compressBound(uLong(index.size()));
		std::string comp(clen, '\0');
		if (compress2(reinterpret_cast<Bytef *>(comp.data()), &clen, reinterpret_cast<const Bytef *>(index.data()),
		              uLong(index.size()), Z_BEST_COMPRESSION) == Z_OK) {
			std::string ih;
			ih += char(1);
			put64(ih, clen);
			put64(ih, index.size());
			write(ih.data(), ih.size());
			write(comp.data(), clen);
			wroteCompressed = true;
		}
	}
#else
	(void)opt;
#endif
	if (!wroteCompressed) {
		std::string ih;
		ih += char(0);
		put64(ih, index.size());
		write(ih.data(), ih.size());
		write(index.data(), index.size());
	}
	const uint64_t endPos = uint64_t(out.tellp());

	out.seekp(std::streamoff(indexPointerPos));
	std::string ptr;
	put64(ptr, indexPos);
	write(ptr.data(), ptr.size());
	if (!out) { error = "writing " + output.string() + " failed"; return false; }
	out.close();
	result.arcBytes = endPos;
	return true;
}

} // namespace xp3crypt

// xp3crypt.hpp - encrypted XP3 archives for the SDL3 Kirikiri Z engine, with no engine
// dependency. The plugin (plugin/) decrypts at run time; this library encrypts (the CLI and a
// game's packaging tool use it) and holds the shared cipher, so both sides agree.
//
// The scheme
//
//   Every file in an archive is stored uncompressed and encrypted with XChaCha20 (Monocypher).
//   The engine's XP3 extraction filter hands the plugin each read as (offset, bytes, fileHash),
//   where fileHash is the 32-bit value in the file's "adlr" index chunk. A stream cipher can
//   seek to any offset, so the filter decrypts reads at any position.
//
//   The packer puts a unique number in each file's adlr chunk (the engine never checks it as a
//   real adler32, and an encrypted file's bytes wouldn't match one anyway), so every file gets a
//   distinct keystream with no risk of two files sharing one. From the game's 32-byte key and a
//   file's adlr number, keyed BLAKE2b derives that file's XChaCha20 key and nonce.
//
//   A stream cipher leaves no place for a whole-file tag, so this doesn't detect tampering; it
//   keeps the files out of plain view. The key ships inside the game (written into the plugin's
//   slot), so a determined person can recover it: this makes casual extraction take real work,
//   not more.
//
// SPDX-License-Identifier: 0BSD

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <set>
#include <string>
#include <vector>

namespace xp3crypt {

using Key = std::array<uint8_t, 32>;

constexpr size_t KEY_SIZE = 32;

//---------------------------------------------------------------------------
// The cipher (decrypting is the same operation as encrypting)
//---------------------------------------------------------------------------

/// XORs `buf` (the `size` bytes at position `offset` of a file whose adlr number is `fileHash`)
/// with that file's keystream for `key`. The plugin calls this to decrypt a read; the packer
/// calls it with offset 0 over a whole file to encrypt it.
void xorFile(uint8_t *buf, size_t size, uint64_t offset, uint32_t fileHash, const Key &key);

//---------------------------------------------------------------------------
// Hashed file names (an archive whose index holds a keyed hash of each path, not the path):
// the packer stores hashName(key, path) as a file's name, and the plugin's storage medium
// resolves a request by hashing it the same way. The hash is keyed with the game key, so the
// hashes differ per game and can't be precomputed or carried from one game to another.
//---------------------------------------------------------------------------

/// A path's stored name: 32 lowercase hex digits, a keyed hash of the normalized path (lower
/// case, '\' as '/', collapsed and no leading '/'). The same path always gives the same name
std::string hashName(const Key &key, const std::string &path);

/// The stored name of a hashed archive's name manifest: an encrypted file, keyed like any
/// other, holding the real paths (one per line) so the plugin can list folders (the engine
/// resolves a bare name by listing the folder it's in). It's hidden among the hashes
std::string manifestName(const Key &key);

//---------------------------------------------------------------------------
// Keys as text and from the system's random source
//---------------------------------------------------------------------------

/// 64 hexadecimal digits (surrounding whitespace ignored) into a key. false + error otherwise;
/// a key of all zeros is rejected (that means "no key")
bool parseKey(const std::string &text, Key &key, std::string &error);

/// A key as 64 lowercase hexadecimal digits
std::string formatKey(const Key &key);

/// A fresh key from the operating system's random source (crypt_random.cpp, which the plugin
/// leaves out). Throws std::runtime_error if the system has no usable source
Key randomKey();

/// Clears a key from memory
void wipe(Key &key);

//---------------------------------------------------------------------------
// The key slot inside a binary (the plugin, or an engine with it built in)
//---------------------------------------------------------------------------

constexpr size_t SLOT_MARKER_SIZE = 16;
constexpr size_t SLOT_SIZE = SLOT_MARKER_SIZE + KEY_SIZE;   // marker then the 32-byte key

/// The marker that precedes the key in the slot
std::array<uint8_t, SLOT_MARKER_SIZE> slotMarker();

/// Every slot's offset in a binary: one, or one per architecture in a universal (fat) Mach-O.
/// Empty with no error means the binary has no slot (not the plugin). error is set on a
/// malformed slot (cut short, or more than the architectures allow)
std::vector<size_t> findSlots(const uint8_t *data, size_t size, std::string &error);

/// The key in a binary's (first) slot. false when there's no slot or it's all zero (no key)
bool readSlot(const uint8_t *data, size_t size, Key &key, std::string &error);

/// Writes `key` into every slot of `binary`. Returns the number written (0 and sets error when
/// there's no slot or it's malformed)
int writeSlots(std::vector<uint8_t> &binary, const Key &key, std::string &error);

//---------------------------------------------------------------------------
// Packing a folder into an encrypted XP3 archive
//---------------------------------------------------------------------------

struct PackOptions {
	bool compressIndex = true;          ///< zlib-compress the file index (when built with zlib)
	bool hashNames = false;             ///< store hashName(key, path) as each file's name
	std::set<std::string> discard;      ///< lowercase ".ext" to leave out (e.g. ".bak")
};

struct PackResult {
	int files = 0;
	uint64_t orgBytes = 0;              ///< total size of the files packed
	uint64_t arcBytes = 0;             ///< size of the archive written
	bool canceled = false;
};

/// name, bytes done, bytes total; return false to cancel
using Progress = std::function<bool(const std::string &, uint64_t, uint64_t)>;

/// Packs the files under `sourceDir` (skipping names that start with '.' and CVS folders) into
/// an encrypted archive at `output`, each file encrypted with `key`. false + error on failure
bool pack(const std::filesystem::path &sourceDir, const std::filesystem::path &output, const Key &key,
          const PackOptions &opt, PackResult &result, std::string &error, const Progress &progress = {});

//---------------------------------------------------------------------------
// Reading an archive's index (for the storage medium and the tests)
//---------------------------------------------------------------------------

struct IndexEntry {
	std::string name;       ///< the stored name (a hash in a hashed archive)
	uint64_t offset = 0;    ///< the file's bytes in the archive
	uint64_t size = 0;
	uint32_t fileHash = 0;  ///< the adlr number (the per-file cipher salt)
};

/// Reads `offset..offset+len` of the archive into `buf`
using Reader = std::function<void(uint64_t offset, void *buf, size_t len)>;

/// Parses an XP3 archive's index through `read` (the archive is `size` bytes). One segment per
/// file is expected (as pack writes). false + error on a malformed archive
bool readIndex(const Reader &read, uint64_t size, std::vector<IndexEntry> &out, std::string &error);

} // namespace xp3crypt

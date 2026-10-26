# xp3crypt

Encrypted XP3 archives for the SDL3 version of Kirikiri Z.

A game's files are packed into `data.xp3` with every file encrypted. The xp3crypt plugin, built
into the engine executable, decrypts each file as the engine reads it, through the engine's XP3
extraction filter. Each game has its own key, written into its copy of the engine when it's
packaged, so prebuilt engines can be used and one game's key doesn't open another's.

**Status:** being written. Nothing here is ready to use yet.

## Parts

- `plugins/xp3crypt/`: the plugin, linked into the engine (`TVP_PLUGINS_STATIC`), so it's in
  place before the engine reads `startup.tjs`
- `lib/`: the cipher, the key format and an encrypted XP3 writer, with no engine code, for
  packaging tools
- `tools/`: `xp3crypt`, a command-line tool that makes keys, packs folders into encrypted
  archives and writes keys into engines
- `tests/`

## Building

```
cmake -B build -DKRKRZ_DEV_DIR=/path/to/krkrz_dev   # plugin needs tp_stub and ncbind from there
cmake --build build
ctest --test-dir build
```

Without a krkrz_dev checkout, build just the library, CLI and tests with `-DXP3CRYPT_PLUGIN=OFF`.

## Using it in a game

1. `xp3crypt keygen game.key` — make the game's key (keep it out of the game's repository).
2. Build the engine with this repository's `plugins/` in `TVP_PLUGIN_FOLDERS` and `xp3crypt` in
   `TVP_PLUGINS_STATIC`, so the plugin is linked into the engine executable.
3. `xp3crypt pack data data.xp3 --keyfile game.key` — pack the game's files, encrypted.
4. `xp3crypt setkey <engine binary> --keyfile game.key` — write the key into the engine.

Ship the engine (with the key) and `data.xp3`. The plugin installs its extraction filter before
`startup.tjs`, so the archive is read transparently. An engine without a key reads a plain
archive, so the same build works with or without encryption.

## License

0BSD (`LICENSE`). Monocypher, which does the encryption, is under BSD-2-Clause or CC0
(`lib/monocypher/LICENCE.md`).

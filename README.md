# xp3crypt

Encrypted XP3 archives for the SDL3 version of Kirikiri Z.

A game's files are packed into `data.xp3` with every file encrypted. The xp3crypt plugin, built
into the engine executable, decrypts each file as the engine reads it, through the engine's XP3
extraction filter. Each game has its own key, written into its copy of the engine when it's
packaged, so prebuilt engines can be used and one game's key doesn't open another's.

**Status:** being written. Nothing here is ready to use yet.

## Parts

- `plugin/`: the plugin, linked into the engine (`TVP_PLUGINS_STATIC`), so it's in place before
  the engine reads `startup.tjs`
- `lib/`: the cipher, the key format and an encrypted XP3 writer, with no engine code, for
  packaging tools
- `tools/`: `xp3crypt`, a command-line tool that makes keys, packs folders into encrypted
  archives and writes keys into engines
- `tests/`

## License

0BSD (`LICENSE`). Monocypher, which does the encryption, is under BSD-2-Clause or CC0
(`lib/monocypher/LICENCE.md`).

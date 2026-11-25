# Windows GM DLS bank conversion

This tool converts the Windows GM DLS bank to SF2 for the FluidSynth renderer.
The generated file stays in the user's cache and is preferred by `audio.py`.

```sh
npm ci
node convert.mjs
```

The default input is `/mnt/c/Windows/System32/drivers/gm.dls` under WSL and
`%WINDIR%\System32\drivers\gm.dls` on Windows. Pass an input DLS path and an
optional output SF2 path to override these defaults.

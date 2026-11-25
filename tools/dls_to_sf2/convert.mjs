#!/usr/bin/env node
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { SoundBankLoader } from "spessasynth_core";

const defaultDls = process.platform === "win32"
  ? path.join(process.env.WINDIR ?? "C:\\Windows", "System32", "drivers", "gm.dls")
  : "/mnt/c/Windows/System32/drivers/gm.dls";
const inputPath = path.resolve(process.argv[2] ?? defaultDls);
const outputPath = path.resolve(process.argv[3] ?? path.join(
  os.homedir(), ".cache", "geki106_re", "soundfonts", "windows_gm_dls.sf2"
));
const temporaryPath = `${outputPath}.tmp`;

const source = await readFile(inputPath);
const inputBuffer = source.buffer.slice(
  source.byteOffset,
  source.byteOffset + source.byteLength
);
const bank = SoundBankLoader.fromArrayBuffer(inputBuffer);
if (bank.presets.length === 0 || bank.samples.length === 0) {
  throw new Error(`No playable instruments or samples found in ${inputPath}`);
}

const soundFont = await bank.writeSF2();
await mkdir(path.dirname(outputPath), { recursive: true });
try {
  await writeFile(temporaryPath, new Uint8Array(soundFont));
  await rm(outputPath, { force: true });
  await rename(temporaryPath, outputPath);
} catch (error) {
  await rm(temporaryPath, { force: true });
  throw error;
}
console.log(`${inputPath} → ${outputPath}`);
console.log(`Converted ${bank.presets.length} presets and ${bank.samples.length} samples`);

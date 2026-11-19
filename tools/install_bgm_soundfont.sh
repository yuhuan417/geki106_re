#!/usr/bin/env bash
# 安装 BGM 渲染用的高质量 GM 音色库（Debian/Ubuntu，无需 root）。
#
# 复刻侧用 fluidsynth 把 extracted/midi/*.mid 离线渲染成 44.1kHz 波形；
# 默认音色库 FluidR3_GM 在 -g 0.62 下高频偏硬、部分曲目会削波。MuseScore
# General 的采样更干净。装到用户目录后 audio.py 会自动优先使用：
#   ~/.local/share/geki106/soundfonts/MuseScore_General_Full.sf3
# 也可用环境变量 GEKI_SF2=/path/to/xxx.sf2 强制指定。
set -euo pipefail

DEST="${HOME}/.local/share/geki106/soundfonts"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

mkdir -p "${DEST}"
cd "${TMP}"
apt-get download musescore-general-soundfont
dpkg-deb -x ./*.deb "${TMP}/x"
cp "${TMP}/x/usr/share/sounds/sf3/MuseScore_General_Full.sf3" "${DEST}/"
echo "installed: ${DEST}/MuseScore_General_Full.sf3"
echo "下次启动会重新渲染缓存的 BGM（/tmp/geki_bgm_*.wav 带音色库 mtime）。"

#!/usr/bin/env bash
# WSL → Windows 音频自检：确认 WSLg 的 PulseAudio 是否真的把声音送到 Windows。
#
#   ./wsl_audio_check.sh          # 全套：服务端 + sink + 播放 + 回环录音
#   ./wsl_audio_check.sh -q       # 只查服务端/sink，不播蜂鸣
#   ./wsl_audio_check.sh -w 5     # 每 5s 探测一次（看声音是否"时好时坏"）
#
# 为什么用回环录音判定：光看 pactl 有 sink 不够（socket 在也能连不上），
# 从 <sink>.monitor 录回来的峰值 > 0 才证明音频数据真的流进了 RDP 音频通道。
# 之后若仍听不到，问题一定在 Windows 侧（音量合成器 / 默认输出设备 / RDP 会话）。
set -uo pipefail

QUIET=0
WATCH=0
case "${1:-}" in
    -q) QUIET=1 ;;
    -w) WATCH=${2:-5} ;;
esac

fail=0
ok()   { printf '  [OK]   %s\n' "$*"; }
bad()  { printf '  [FAIL] %s\n' "$*"; fail=1; }
warn() { printf '  [WARN] %s\n' "$*"; }
hr()   { printf '\n== %s ==\n' "$*"; }

hr "0. WSLg 健康状态"
if [[ -d /mnt/wslg ]]; then
    ok "/mnt/wslg 存在（WSLg 已启用）"
else
    bad "没有 /mnt/wslg：WSLg 未启用（需要 Win11 或 Win10 21H2+，且 .wslconfig 里 guiApplications=true）"
    exit 1
fi
CRASH=0
if [[ -f /mnt/wslg/stderr.log ]]; then
    CRASH=$(grep -c 'terminated with signal 11' /mnt/wslg/stderr.log 2>/dev/null || true)
    LAST=$(grep 'terminated with signal 11' /mnt/wslg/stderr.log 2>/dev/null | tail -1 | sed 's/^\[\([^]]*\)\].*/\1/')
    if [[ "${CRASH:-0}" -gt 0 ]]; then
        bad "Weston（WSLg 合成器）已崩溃 ${CRASH} 次，最后一次 ${LAST}"
        warn "每次崩溃都连带重启 msrdc.exe —— RDP 音频通道随之消失，这就是\"完全没声音\"的典型原因"
    else
        ok "Weston 未崩溃"
    fi
fi

hr "1. PulseAudio 服务端"
if ! command -v pactl >/dev/null 2>&1; then
    bad "缺 pactl：apt install -y pulseaudio-utils"
    exit 1
fi
printf '  PULSE_SERVER=%s\n' "${PULSE_SERVER:-<未设置>}"
if pactl info >/dev/null 2>&1; then
    pactl info | grep -E '^(Server Name|Server Version|Default Sink|Default Source)' | sed 's/^/  /'
    ok "服务端可连接"
else
    bad "pactl info 失败：连不上 ${PULSE_SERVER:-PulseAudio}"
    exit 1
fi

hr "2. 输出 sink"
SINK=$(pactl get-default-sink 2>/dev/null || pactl info | awk -F': ' '/^Default Sink:/{print $2}')
printf '  使用 sink: %s\n' "${SINK:-<无>}"
[[ -z "${SINK:-}" ]] && { bad "没有任何 sink —— WSLg 音频模块没起来"; exit 1; }
pactl list short sinks | sed 's/^/  /'

sink_prop() {   # $1 = state | mute | volume
    python3 - "$SINK" "$1" <<'PY'
import json, subprocess, sys
sink, prop = sys.argv[1], sys.argv[2]
out = subprocess.run(["pactl", "-f", "json", "list", "sinks"], capture_output=True, text=True).stdout
data = json.loads(out or "[]")
for s in data:
    if s.get("name") != sink:
        continue
    if prop == "state":
        print(s.get("state", "?"))
    elif prop == "mute":
        print("yes" if s.get("mute") else "no")
    elif prop == "volume":
        v = list(s.get("volume", {}).values())
        print(f"{v[0].get('value_percent', '?')} @ {v[0].get('db', '?')}" if v else "?")
    break
PY
}
MUTE=$(sink_prop mute)
if [[ "$MUTE" == "yes" ]]; then
    bad "sink 被静音（解除：pactl set-sink-mute $SINK 0）"
else
    ok "sink 未静音"
fi
printf '  音量: %s\n' "$(sink_prop volume)"

if [[ $QUIET -eq 1 ]]; then
    printf '\n(静默模式，跳过播放/回环测试)\n'
    exit $fail
fi

hr "3. 播放 + 回环验证"
command -v paplay >/dev/null || { bad "缺 paplay：apt install -y pulseaudio-utils"; exit 1; }
command -v parec  >/dev/null || { bad "缺 parec：apt install -y pulseaudio-utils"; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
python3 - "$TMP/beep.wav" <<'PY'
import math, struct, sys, wave
sr, dur = 44100, 2.0
with wave.open(sys.argv[1], 'wb') as w:
    w.setnchannels(2); w.setsampwidth(2); w.setframerate(sr)
    buf = bytearray()
    for i in range(int(sr * dur)):
        env = min(1.0, i / (0.05 * sr), (sr * dur - i) / (0.05 * sr))
        v = int(12000 * env * math.sin(2 * math.pi * 440 * i / sr))
        buf += struct.pack('<hh', v, v)
    w.writeframes(bytes(buf))
PY
ok "已生成 2.0s / 440Hz 蜂鸣（峰值 12000）"

# 注意顺序：**先开录音再播放**。parec 连上 monitor 要 1s 左右（sink 从挂起唤醒更慢），
# 反过来做会把整段蜂鸣错过、录到一串静音，误判成"没声音"。
probe() {   # 播一次蜂鸣并回环录音，设置 STATE / PEAK / BYTES
    timeout 4 parec --device="$SINK.monitor" --format=s16le --rate=44100 --channels=2 \
        --raw > "$TMP/rec.raw" 2>/dev/null &
    local rec=$!
    sleep 0.8
    paplay "$TMP/beep.wav" &
    local pid=$!
    sleep 1.0          # paplay 自己也要 ~0.5s 才把流建起来，太早采样会读到 IDLE
    STATE=$(sink_prop state)
    wait "$pid" 2>/dev/null
    wait "$rec" 2>/dev/null
    PEAK=$(python3 - "$TMP/rec.raw" <<'PY'
import struct, sys
data = open(sys.argv[1], 'rb').read()
data = data[:len(data) // 2 * 2]
vals = struct.unpack('<%dh' % (len(data) // 2), data) if data else ()
print(max((abs(v) for v in vals), default=0))
PY
)
    BYTES=$(stat -c%s "$TMP/rec.raw")
}

if [[ "$WATCH" -gt 0 ]]; then
    printf '  循环探测：每 %ss 播一次蜂鸣（Ctrl-C 结束）。peak>500 = 这一刻音频通\n' "$WATCH"
    while :; do
        probe
        printf '[%s] peak=%-6s sink=%-9s crash=%s\n' \
            "$(date +%T)" "$PEAK" "${STATE:-?}" "$(grep -c 'signal 11' /mnt/wslg/stderr.log 2>/dev/null || true)"
        sleep "$WATCH"
    done
fi

probe
printf '  播放中 sink 状态: %s（本 build 播放时也常报 IDLE，仅作参考）\n' "${STATE:-?}"
case "${STATE:-}" in
    RUNNING) ok "sink 正在运行（数据在流出）" ;;
    IDLE)    ok "sink 已接收流（状态机报 IDLE，以回环峰值为准）" ;;
    *)       warn "状态 ${STATE:-?}（以回环峰值为准）" ;;
esac
printf '  回环录音: %s 字节, 峰值 %s\n' "$BYTES" "$PEAK"

hr "判定"
if [[ "$PEAK" -gt 500 ]]; then
    ok "WSL 侧完整：音频已进入 ${SINK}，正送往 Windows 的音频重定向通道"
    cat <<'MSG'

  若耳朵仍没听到，问题一定在 Windows 侧，依次检查：
   1. 右下角音量图标 → 输出设备是不是你以为的那只（HDMI / 蓝牙 / 显示器最爱抢默认）
   2. 打开「音量合成器」，看播放期间是否出现 WSL / wslg 条目，是否被单独静音或拉到 0
   3. 若正通过远程桌面(RDP)连这台机器：RDP 会禁用 WSLg 音频，请在物理机桌面会话里测
MSG
elif [[ "$PEAK" -gt 0 ]]; then
    warn "有信号但很弱（峰值 $PEAK）：重跑一次，或 sink 音量被调得很低"
else
    bad "回环录音全 0：数据根本没进 sink"
    if [[ "${CRASH:-0}" -gt 0 ]]; then
        cat <<'MSG'

  对应上面第 0 步：Weston 在崩溃循环里（rdp-backend.so 段错误），RDP 音频端点每次崩溃后都
  重建失败。处理顺序（都要在 Windows 终端里做）：
     wsl --update          # 让 WSLg 与内核/WSL 版本匹配，修 rdp-backend 崩溃
     wsl --shutdown        # 重启 WSLg（会杀掉当前所有 WSL 进程）
     重新打开 WSL，跑 ./wsl_audio_check.sh 复验
  日志证据：
     /mnt/wslg/stderr.log      Weston 崩溃/重启记录（signal 11）
     /mnt/wslg/pulseaudio.log  rdp-sink "Connected failed" 刷屏
     dmesg | grep -i weston    segfault at ... in rdp-backend.so
MSG
    else
        cat <<'MSG'

  Weston 没崩但数据进不去 sink，按顺序尝试：
     pactl set-sink-mute "$(pactl get-default-sink)" 0
     pactl set-sink-volume "$(pactl get-default-sink)" 100%
     仍有问题：wsl --shutdown 后重开（重启 WSLg 的 pulseaudio）
MSG
    fi
fi
exit $fail

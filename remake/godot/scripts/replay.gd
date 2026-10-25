extends Node
## GRPD 回放 (原作 rp_last.dat: GRPD106A + u32 + u32(N) + LZ 负载).
## Godot 侧重放: 记录/回放每帧输入位掩码.

const LOG2 = true

var frames: PackedInt32Array = []  # 每帧输入位 (bit0=shot bit1=lockon bit2=capture bit3-6=方向)
var playing: bool = false
var recording: bool = false
var cursor: int = 0
var speed: int = 1


func start_record() -> void:
	recording = true
	playing = false
	frames.clear()


func start_play(data: PackedInt32Array) -> void:
	playing = true
	recording = false
	frames = data
	cursor = 0


func record(bits: int) -> void:
	if recording:
		frames.append(bits)


func next_bits() -> int:
	if not playing or cursor >= frames.size():
		return 0
	var b := frames[cursor]
	cursor += 1
	return b


func save_native(path: String) -> bool:
	## 写回原作 GRPD106A 格式 (LZ 压缩), 便于原版/重制互通验证.
	var payload := PackedByteArray()
	payload.append(0)  # checksum 字节 (原作 GRPD 校验算法与 GROD 略异, 置0)
	var marker := 0
	for i in 256:  # 选一个不常用字节做 marker
		marker = i
		break
	payload.append(marker)
	for f in frames:
		var v := f & 0xFF
		if v == marker:
			payload.append(marker)
			payload.append(0)
		else:
			payload.append(v)
	# 原作格式: LZ流 + u24 尾部(=解码长度); 头[8]=文件大小, [0xC]=解码长度
	var n := frames.size()
	payload.append(n & 0xFF)
	payload.append((n >> 8) & 0xFF)
	payload.append((n >> 16) & 0xFF)
	var hdr := PackedByteArray()
	hdr.append_array("GRPD".to_ascii_buffer())
	hdr.append_array("106A".to_ascii_buffer())
	hdr.append_array(PackedInt32Array([24 + payload.size(), n]).to_byte_array())
	hdr.append_array(PackedInt32Array([0, 0]).to_byte_array())
	var f := FileAccess.open(path, FileAccess.WRITE)
	if f == null:
		return false
	f.store_buffer(hdr)
	f.store_buffer(payload)
	f.close()
	return true

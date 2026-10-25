extends Node
## 关卡脚本 VM (geki106.exe 0x460350 的 1:1 移植)
## 记录: {op, t, ...} 由 build_assets.py 从原始脚本编译为 JSON.

var out_queue: Array = []  # 待处理命令 (替代信号, 更直接)
signal next_stream
signal set_param(arg: int)
signal layers_init(vals: Array)

var records: Array = []
var pos: int = 0
var frame: int = 0
var done: bool = false
var transition_arg = null
var stream_name: String = ""


func load_stream(recs: Array) -> void:
	# JSON 数字解析为 float; GDScript match 是类型严格的 — 归一化整数字段
	for r in recs:
		r.op = int(r.op)
		r.t = int(r.t)
		if r.has("ch"):
			r.ch = int(r.ch)
	records = recs
	pos = 0
	frame = 0
	done = false


func tick() -> void:
	## 一帧: 消化所有 t<=frame 的记录 (与原作一致)
	while not done and pos < records.size():
		var r: Dictionary = records[pos]
		if r.t > frame:
			break
		_exec(r)
		if r.op == 0:
			break
		pos += 1
	frame += 1


func _exec(r: Dictionary) -> void:
	match r.op:
		0x0:
			done = true
			next_stream.emit()
		0x1, 0x2, 0x3, 0x4, 0x5:
			out_queue.append(r)
		0x6:
			# 发射器一次性触发 — 由 Game 侧 EmitterBank 处理
			out_queue.append(r)
		0x7:
			out_queue.append(r)
		0x8:
			out_queue.append(r)
		0x9, 0xA:
			out_queue.append(r)
		0xB:
			layers_init.emit(r.layers)
		0xC:
			transition_arg = r.arg
		0xD:
			set_param.emit(r.arg)
		0xE:
			stream_name = r.name

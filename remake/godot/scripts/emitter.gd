extends Node
## 弹幕发射器库 (geki106.exe 0x457C00/0x456D80/0x457380 的 1:1 移植)
## 12 通道; 每通道 state[20] + delta[20] (原作 16.16 定点, 此处用 float).
## 已知 state 下标: 10/11=rand散布, 12=间隔阈值, 13=速率, 15..18=外观权重.

const N_CH := 12
const INTERVAL := 12
const RATE := 13

var ch_state: Array = []      # 每通道 [20 float]
var ch_delta: Array = []
var ch_active: Array = []
var ch_burst: Array = []
var ch_accum: Array = []
var fired: Array = []         # 本帧新弹 (Game 取走)
var rng := RandomNumberGenerator.new()


func _init() -> void:
	for i in N_CH:
		ch_state.append(PackedFloat32Array())
		ch_state[i].resize(20)
		ch_delta.append(PackedFloat32Array())
		ch_delta[i].resize(20)
		ch_active.append(false)
		ch_burst.append(0)
		ch_accum.append(0.0)


func one_shot(idx: int, delta: Array, burst: float) -> void:
	if idx >= N_CH:
		for i in N_CH:
			_define(i, delta, burst, true)
	else:
		_define(idx, delta, burst, true)


func define(idx: int, delta: Array, burst: float) -> void:
	if idx >= N_CH:
		for i in N_CH:
			_define(i, delta, burst, false)
	else:
		_define(idx, delta, burst, false)


func stop(idx: int) -> void:
	if idx >= N_CH:
		for i in N_CH:
			ch_active[i] = false
	else:
		ch_active[idx] = false


func _define(idx: int, delta: Array, burst: float, activate: bool) -> void:
	if activate:
		ch_active[idx] = true
	elif not ch_active[idx]:
		return  # 原作: 未激活通道的定义被忽略
	ch_burst[idx] = burst
	for i in 20:
		ch_delta[idx][i] = delta[i]


func update() -> void:
	fired.clear()
	for c in N_CH:
		if not ch_active[c]:
			continue
		var st: PackedFloat32Array = ch_state[c]
		var dl: PackedFloat32Array = ch_delta[c]
		for i in 20:
			st[i] += dl[i]
		if ch_burst[c] > 0:
			_fire(c)
			ch_burst[c] -= 1
		ch_accum[c] += st[RATE]
		if absf(ch_accum[c]) >= st[INTERVAL]:
			if st[RATE] >= 0.0:
				ch_accum[c] = absf(ch_accum[c]) - st[INTERVAL]
			else:
				ch_accum[c] = st[INTERVAL] - absf(ch_accum[c])
			_fire(c)


func _fire(c: int) -> void:
	var st: PackedFloat32Array = ch_state[c]
	var jx := rand_to(st[10])
	var jy := rand_to(st[11])
	var weights := [maxf(st[15], 0.0), maxf(st[16], 0.0), maxf(st[17], 0.0), maxf(st[18], 0.0)]
	var total: float = weights[0] + weights[1] + weights[2] + weights[3]
	var kind := 0
	if total > 0.0:
		var r := rng.randf() * total
		for i in 4:
			if r < weights[i]:
				kind = i
				break
			r -= weights[i]
	fired.append({
		"x": st[0] + jx, "y": st[1] + jy,
		"vx": st[2], "vy": st[3],
		"kind": kind,
	})


func rand_to(v: float) -> float:
	if v <= 0.0:
		return 0.0
	return float(rng.randi() % int(v + 1.0))

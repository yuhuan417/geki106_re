extends Node
## 敌机行为库 — 从 exe 行为函数还原 (ANALYSIS.md §19.1)
## 字段语义: +4=x +8=y +0x14=cmd.c +0x1C=param/leader +0x20/+0x24/+0x28=vx/vy/acc +0x2C=phase
## 玩家坐标原作全局: 0x56CC8C(x) 0x56CC90(y)

static var player_x := 370.0
static var player_y := 240.0


## 行为分派: 由 cmd.c 决定 (sub-variant = c-0x23000001, 表外=直线)
static func update(e: Dictionary, spawn_fn: Callable, fire_fn: Callable) -> bool:
	var c: int = e.cmd
	var t: int = (c >> 24) & 0xFF
	var sub: int = c - 0x23000001
	match t:
		0x21:
			if c == 0x21000001:
				return _aimed(e, fire_fn)
			return _line(e)
		0x23:
			if sub >= 0 and sub < 26:
				return _variant(e, sub, spawn_fn, fire_fn)
			return _line(e)          # 0x230002xx 通用: 匀速左飞
		0x24, 0x29:
			return _line(e)
		_:
			return _line(e)
	return _line(e)


static func _step(e: Dictionary) -> void:
	e.x += e.vx
	e.y += e.vy
	e.phase += 1
	e.angle = atan2(e.y - player_y, e.x - player_x)


static func _line(e: Dictionary) -> bool:
	_step(e)
	return e.x > -40.0 and e.x < 720.0 and e.y > -60.0 and e.y < 540.0


static func _aimed(e: Dictionary, fire_fn: Callable) -> bool:
	## 0x21000001: 出现时朝玩家方向瞄准 (原作 atan2(x-24, y-24))
	if e.phase == 0:
		e.vx = (player_x - e.x)
		e.vy = (player_y - e.y)
		var l := sqrt(e.vx * e.vx + e.vy * e.vy)
		if l > 0.0:
			e.vx = e.vx / l * 3.0
			e.vy = e.vy / l * 3.0
	_step(e)
	if e.phase % 40 == 20:
		fire_fn.call(e)
	return e.x > -40.0 and e.x < 700.0


## 0x23 型 26 子变体 (跳转表 0x40DE98) -> 行为函数映射
static func _variant(e: Dictionary, sub: int, spawn_fn: Callable, fire_fn: Callable) -> bool:
	match sub:
		0: return _curve_phases(e, fire_fn)      # 0x401FF0
		1: return _zone_velocity(e, fire_fn)     # 0x401B1D
		2, 3, 4: return _spawner(e, fire_fn, spawn_fn)  # 0x401BD1
		5: return _aimed_spawn(e, spawn_fn)      # 0x401528
		6, 7: return _player_sine(e, fire_fn)    # 0x4015AA/0x401181
		8: return _sine(e)                       # 0x401181 (-6,-48)
		9: return _player_escort(e)              # 0x401609
		11, 12: return _spawner(e, fire_fn, spawn_fn)   # 0x401BA9
		14, 15, 16: return _dived(e, fire_fn)    # 0x401DC5 (俯冲)
		17: return _curve_phases(e, fire_fn)     # 0x4015B4 (近似 0x401FF0 族)
		22: return _zigzag(e)                    # 0x4013BB (-24, +15)
		24, 25: return _dive_fast(e)             # 0x40242D (-64)
		_: return _line(e)


## 0x401FF0: 分段变加速 (帧 20-39 加速 / 40-59 反向 / 140+ 水平机动), x=400 开火
static func _curve_phases(e: Dictionary, fire_fn: Callable) -> bool:
	var p: int = e.phase
	var a: float = e.get("p20", 1.0)
	if p >= 20 and p < 40:
		e.acc += a
	elif p >= 40 and p < 60:
		e.acc -= a
	elif p >= 140 and p < 156:
		e.vx += 1.0
		e.acc += a
	elif p >= 156 and p < 172:
		e.vx += 1.0
		e.acc -= a
	e.x += (e.vx + 2.0) / 4.0
	e.y += (e.acc + 2.0) / 4.0
	e.phase += 1
	e.angle = atan2(e.y - 24.0, e.x - 24.0)
	if abs(e.x - 400.0) < 1.0 and e.get("p1c", 0) == 1:
		fire_fn.call(e)
	return e.x < 680.0


## 0x401B1D: x 区间速度切换 + 开火
static func _zone_velocity(e: Dictionary, fire_fn: Callable) -> bool:
	var x: float = e.x - 240.0
	if x >= 0.0 and x < 242.0:
		var zone := 0  # 原作查表, 区间细分; 近似取三段
		if x < 80.0:
			e.vx = -1.0
			e.vy = 2.0 if e.y <= 240.0 else -2.0
		elif x < 160.0:
			e.vx = -3.0
			e.vy = 0.0
		else:
			if e.get("p1c", 0) != 0:
				fire_fn.call(e)
	_step(e)
	return e.x > -24.0


## 0x401BD1: 繁殖型 — 生成 N 个 0x23000006 子机(镜像位置) + 阶段变速 + vx==0x172(370) 开火
static func _spawner(e: Dictionary, fire_fn: Callable, spawn_fn: Callable) -> bool:
	var n: int = e.get("p2c", 0)
	while n > 0:
		spawn_fn.call({
			"cmd": 0x23000006, "x": e.x, "y": e.y + (e.get("spawn_off", 0.0)),
			"vx": -3.0, "vy": 0.0, "hp": 4, "w": 16.0, "h": 16.0, "phase": 0, "age": 0,
		})
		n -= 1
	e["p2c"] = 0
	if e.get("p1c", 0) == 0 and e.cmd != 0x23000005 and abs(e.vx - 370.0) < 1.0:
		fire_fn.call(e)
	return _line(e)


static func _aimed_spawn(e: Dictionary, spawn_fn: Callable) -> bool:
	if e.phase == 0:
		spawn_fn.call({
			"cmd": 0x23000006, "x": e.x, "y": e.y,
			"vx": signf(player_x - e.x) * 2.0, "vy": signf(player_y - e.y) * 2.0,
			"hp": 4, "w": 16.0, "h": 16.0, "phase": 0, "age": 0,
		})
	return _line(e)


## 0x401181: 正弦 — y = 456 + (acc>>3), acc += vx周期, 周期点翻转/开火
static func _sine(e: Dictionary) -> bool:
	e.p20 += 1.0
	if int(e.p20) == 0 or int(e.p20) == 48:
		e.vx = -e.vx
		e.p20 = -47.0 if e.p20 == 48 else e.p20
	e.acc += e.p20
	e.x += e.vx
	e.y = 456.0 + e.acc / 8.0
	e.phase += 1
	e.angle = atan2(e.y - player_y, e.x - player_x)
	return e.x > -24.0


static func _player_sine(e: Dictionary, fire_fn: Callable) -> bool:
	var r := _sine(e)
	if e.phase % 50 == 25:
		fire_fn.call(e)
	return r


## 0x401609: 僚机跟随 — 追踪玩家位置保持偏移
static func _player_escort(e: Dictionary) -> bool:
	var dx: float = (player_x + e.get("p1cf", 60.0)) - e.x
	var dy: float = (player_y + e.get("p24f", 0.0)) - e.y
	e.vx = dx / 8.0
	e.vy = dy / 8.0
	_step(e)
	return e.x > -60.0


## 0x401DC5: 俯冲 — 短暂悬停后朝玩家加速
static func _dived(e: Dictionary, fire_fn: Callable) -> bool:
	if e.phase < 36:
		e.vx = 0.0
		e.vy = 0.0
	else:
		var dx: float = player_x - e.x
		var dy: float = player_y - e.y
		var l := sqrt(dx * dx + dy * dy)
		if l > 0.0:
			e.vx = dx / l * 5.0
			e.vy = dy / l * 5.0
	if e.phase == 36:
		fire_fn.call(e)
	_step(e)
	return e.x > -40.0 and e.y > -40.0 and e.y < 520.0


## 0x4013BB: 之字 (-24, +15 常量)
static func _zigzag(e: Dictionary) -> bool:
	e.vx = -24.0 / 8.0
	e.vy = (15.0 / 8.0) * (1.0 if (e.phase / 24) % 2 == 0 else -1.0)
	_step(e)
	return e.x > -24.0


## 0x40242D: 快速俯冲 (-64)
static func _dive_fast(e: Dictionary) -> bool:
	e.vx = -64.0 / 8.0
	if e.y < player_y:
		e.vy += 0.25
	else:
		e.vy -= 0.25
	_step(e)
	return e.x > -24.0

extends Node2D
## 撃破伝重制版主场景 — 640x480 横版弹幕.
## 资产由 build_assets.py 从原版资源编译; 脚本/发射器为原作逻辑的 1:1 移植.

const W := 640
const H := 480
const STAGE_STREAMS := {1: 46, 2: 47, 3: 48, 4: 49, 5: 50, 6: 51, 7: 52}

var stage: int = 1
var frame: int = 0
var mode: String = "title"   # title | game | gameover
var player_lives := 3


func _restart() -> void:
	get_tree().reload_current_scene()
var score: int = 0
var paused: bool = false

# 系统
var vm: Node
var emitters: Node
var audio: Node
var replay: Node
var behaviors: Node
var bganim_frames: Array = []
var bganim_pos: int = 0
var pattern_layers: Dictionary = {}   # 7..10 -> Image
var bg_tex: Texture2D
var bg_img: Image
var hud_font: Font
var kanji_font: Font
# 实体汉字渲染 (原作 0x44D330: CreateFontIndirect(高=size,宽=size/2)+SetTextColor+TextOutA)
# 字符映射: 从实机截图校准 — 自机绿, 敌机橙红方块字, 弹为小字
# ===== 真实字形位图 (用户确认: otc=战机 bm_s1=敌人 cm32=子弹) =====
var ship_tex: Texture2D = null
var ship_big: Texture2D = null
var enemy_texes: Array = []
var bullet_texes: Array = []
const PLAYER_KANJI := "撃"          # 自机 = 标题字"撃"
const BULLET_P_KANJI := "弾"         # 自机基本弹
const BULLET_AIMED := "狙"           # 强力瞄准弹 (敌开火)
const SCENERY_KANJI := "雲"          # 开场天景 (背景发射器)
const ENEMY_KANJI := {0x23: "弱", 0x24: "田", 0x21: "由", 0x29: "甲"}  # 首波敌=弱(实测)
const BULLET_E_KANJI := ["雲", "雲", "雲", "雲"]  # 背景发射器弹=雲(实测, 天景)
const HUD_LEFT := ["雷", "炸", "連"]

# 实体 (16.16 定点语义已转为 float 像素)
var player := {"x": 80.0, "y": 240.0, "w": 16.0, "h": 16.0, "cool": 0}
var enemies: Array = []
var bullets_e: Array = []
var bullets_p: Array = []

# 调试/验证
var auto_quit_frames: int = -1
var logic_only: bool = false


func _ready() -> void:
	# 页1-3 由 remake/pygame 复刻（本工程只保留游戏本体页4 的移植）
	stage = int(OS.get_environment("GEKI_STAGE")) if OS.get_environment("GEKI_STAGE") != "" else 1
	if OS.get_environment("GEKI_STAGE") != "":
		mode = "game"  # 指定关卡 = 直接进游戏 (验证模式)
	var aq := OS.get_environment("GEKI_FRAMES")
	if aq != "":
		auto_quit_frames = int(aq)
	logic_only = OS.get_environment("GEKI_LOGIC") == "1"

	var vm_script: GDScript = load("res://scripts/script_vm.gd")
	var em_script: GDScript = load("res://scripts/emitter.gd")
	vm = vm_script.new()
	add_child(vm)
	emitters = em_script.new()
	add_child(emitters)
	var audio_script: GDScript = load("res://scripts/audio.gd")
	audio = audio_script.new()
	add_child(audio)
	audio.play_bgm(stage + 1)  # BGM 资源 #N+1 对应关卡 N (近似映射, 待原作确认)
	var bh_script: GDScript = load("res://scripts/behaviors.gd")
	behaviors = bh_script.new()
	add_child(behaviors)
	var rp_script: GDScript = load("res://scripts/replay.gd")
	replay = rp_script.new()
	add_child(replay)
	replay.start_record()
	var ba = JSON.parse_string(FileAccess.get_file_as_string("res://assets/scripts/bganim.json"))
	if ba != null:
		bganim_frames = ba
	for L in [7, 8, 9, 10]:
		var p := "res://assets/patterns/layer%d.png" % L
		if ResourceLoader.exists(p):
			var t = load(p)
			if t != null and t.has_method("get_image"):
				var im = t.get_image()
				if im != null:
					if im.get_format() != Image.FORMAT_RGBA8:
						im.convert(Image.FORMAT_RGBA8)
					pattern_layers[L] = im

	var path := "res://assets/scripts/stage_%d.json" % stage
	var json: Variant = JSON.parse_string(FileAccess.get_file_as_string(path))
	vm.load_stream(json as Array)
	bg_tex = load("res://assets/bg/stage_%d.png" % (stage - 1))
	bg_img = bg_tex.get_image()
	if bg_img != null and bg_img.get_format() != Image.FORMAT_RGBA8:
		bg_img.convert(Image.FORMAT_RGBA8)
	hud_font = ThemeDB.fallback_font
	var fp := "res://assets/fonts/NotoSansCJK-Bold.ttc"
	if ResourceLoader.exists(fp):
		kanji_font = load(fp)
	_ship_load()


var _events: Array = []


func _physics_process(_delta: float) -> void:
	if mode == "title":
		frame += 1
		queue_redraw()
		if Input.is_action_just_pressed("shot"):
			mode = "game"
			frame = 0
			audio.play_bgm(stage + 1)
		if auto_quit_frames > 0 and frame >= auto_quit_frames:
			_finish()
		return
	if mode == "gameover":
		frame += 1
		queue_redraw()
		if Input.is_action_just_pressed("shot") or frame > 3600:
			_restart()
		if auto_quit_frames > 0 and frame >= auto_quit_frames:
			_finish()
		return
	if paused:
		return
	frame += 1
	replay.record(_input_bits())
	if bganim_pos < bganim_frames.size():
		for r in bganim_frames[bganim_pos]:
			_bg_blit(r)
		bganim_pos += 1
	vm.tick()
	for r in vm.out_queue:
		_on_cmd(int(r.op), r)
	vm.out_queue.clear()
	if vm.transition_arg != null:
		_events.append("transition:%d" % vm.transition_arg)
		vm.transition_arg = null
	emitters.update()
	_collect_bullets()
	_move_player()
	_fire_player()
	_update_entities()
	_collide()
	queue_redraw()
	if auto_quit_frames > 0 and frame >= auto_quit_frames:
		_finish()


func _finish() -> void:
	replay.save_native("res://rp_last.dat")
	print("frames=%d score=%d enemies=%d ebullets=%d events=%s" % [frame, score, enemies.size(), bullets_e.size(), str(_events).substr(0, 120)])
	var img = get_viewport().get_texture().get_image()
	if img != null:
		img.save_png("res://godot_frame%d.png" % frame)
	get_tree().quit()


# ------------------------------------------------------------ 脚本命令
func _on_cmd(op: int, r: Dictionary) -> void:
	match op:
		0x2:  # 敌机生成 (x, y, type<<24|param, flag)
			var tp := int(r.args[2])
			enemies.append({
				"cmd": tp, "x": float(r.args[0]), "y": float(r.args[1]),
				"vx": -2.0, "vy": 0.0, "acc": 0.0, "hp": 8,
				"type": tp >> 24, "param": tp & 0xFFFFFF,
				"p1c": int(r.args[3]) & 1, "p20": 1.0, "angle": 0.0,
				"w": 24.0, "h": 24.0, "age": 0, "phase": 0,
			})
		0x6:
			emitters.one_shot(r.ch, r.delta, float(r.tail[0]))
		0x7:
			emitters.define(r.ch, r.delta, float(r.tail[0]))
		0x8:
			emitters.stop(r.ch)


func _collect_bullets() -> void:
	for b in emitters.fired:
		bullets_e.append({"x": b.x, "y": b.y, "vx": b.vx, "vy": b.vy,
			"kind": b.kind, "w": 6.0, "h": 6.0, "ch": SCENERY_KANJI})
	emitters.fired.clear()


# ------------------------------------------------------------ 玩家
func _move_player() -> void:
	var v := Vector2(
		Input.get_axis("ui_left", "ui_right"),
		Input.get_axis("ui_up", "ui_down"))
	player.x = clampf(player.x + v.x * 5.0, 8.0, W - 8.0)
	player.y = clampf(player.y + v.y * 5.0, 8.0, H - 8.0)
	if not (Input.get_mouse_mode() & 1) == 0:
		pass


func _fire_player() -> void:
	if player.cool > 0:
		player.cool -= 1
	if Input.is_action_pressed("lockon"):
		_do_lockon()
	if Input.is_action_just_pressed("capture"):
		_do_capture()
	if Input.is_action_pressed("shot") and player.cool == 0:
		bullets_p.append({"x": player.x + 14.0, "y": player.y, "vx": 12.0, "vy": 0.0, "w": 10.0, "h": 8.0})
		player.cool = 5
		audio.se(21, -6.0)


func _ship_load() -> void:
	var ship_id := clampi(int(OS.get_environment("GEKI_SHIP")), 0, 2) if OS.get_environment("GEKI_SHIP") != "" else 0
	var p := "res://assets/glyphs/ship%d.png" % ship_id
	if ResourceLoader.exists(p):
		var t = load(p)
		if t != null and t.has_method("get_image") and t.get_image() != null:
			ship_tex = ImageTexture.create_from_image(t.get_image())
	for i in 24:
		var e := "res://assets/glyphs/enemy_s%d_%02d.png" % [stage, i]
		if ResourceLoader.exists(e):
			var te = load(e)
			if te is Texture2D:
				enemy_texes.append(te)
	for i in 80:
		var b := "res://assets/glyphs/bullet_%02d.png" % i
		if ResourceLoader.exists(b):
			var tb = load(b)
			if tb is Texture2D:
				bullet_texes.append(tb)


func _input_bits() -> int:
	var b := 0
	if Input.is_action_pressed("shot"):
		b |= 1
	if Input.is_action_pressed("lockon"):
		b |= 2
	if Input.is_action_pressed("capture"):
		b |= 4
	if Input.is_action_pressed("ui_left"):
		b |= 8
	if Input.is_action_pressed("ui_right"):
		b |= 16
	if Input.is_action_pressed("ui_up"):
		b |= 32
	if Input.is_action_pressed("ui_down"):
		b |= 64
	return b


func _do_lockon() -> void:
	## 锁定: 自机右侧最近的敌机受到持续光束伤害 (MaxLaserHit 统计来源)
	var best = null
	var bestd := 1e9
	for e in enemies:
		if e.x > player.x and absf(e.y - player.y) < 60.0:
			var d := absf(e.x - player.x) + absf(e.y - player.y)
			if d < bestd:
				bestd = d
				best = e
	if best != null:
		best.hp -= 0.5
		_laser_target = best
		if best.hp <= 0:
			enemies.erase(best)
			score += 150
			_events.append("lockkill")


func _do_capture() -> void:
	## 捕获: 半径内敌弹转化为分数 (readme: 捕獲)
	var taken := 0
	for b in bullets_e.duplicate():
		if absf(b.x - player.x) < 90.0 and absf(b.y - player.y) < 90.0:
			bullets_e.erase(b)
			taken += 1
	if taken > 0:
		score += taken * 10
		_events.append("capture:%d" % taken)


var _laser_target = null


func _bg_blit(r: Dictionary) -> void:
	## #77 = 背景天空本体: Blt(主屏@rect1, 天空图案层7-10@rect2) — exe 0x44D0B0
	if bg_img == null:
		return
	var src_img: Image = pattern_layers.get(int(r.layer))
	if src_img == null:
		return
	var sx := int(r.sx); var sy := int(r.sy)
	var sw := int(r.sw); var sh := int(r.sh)
	var dw := int(r.dw); var dh := int(r.dh)
	if dw <= 0 or dh <= 0 or sw <= 0 or sh <= 0:
		return
	if sx < 0 or sy < 0 or sx + sw > src_img.get_width() or sy + sh > src_img.get_height():
		return
	var tile: Image = src_img.get_region(Rect2i(sx, sy, sw, sh))
	if tile == null or tile.is_empty():
		return
	if tile.get_format() != bg_img.get_format():
		tile.convert(bg_img.get_format())
	if sw != dw or sh != dh:
		tile.resize(dw, dh)
	bg_img.blend_rect(tile, Rect2i(0, 0, dw, dh), Vector2i(int(r.dx), int(r.dy)))


func _update_entities() -> void:
	behaviors.player_x = player.x
	behaviors.player_y = player.y
	for e in enemies.duplicate():
		var alive: bool = behaviors.update(e, _spawn_child, _enemy_fire)
		e.age += 1
		if not alive or e.hp <= 0:
			if e.hp <= 0:
				score += 100
			enemies.erase(e)
	for b in bullets_e:
		b.x += b.vx
		b.y += b.vy
	bullets_e = bullets_e.filter(func(b): return b.x > -40.0 and b.x < W + 40.0 and b.y > -40.0 and b.y < H + 40.0)
	for b in bullets_p:
		b.x += b.vx
		b.y += b.vy
	bullets_p = bullets_p.filter(func(b): return b.x < W + 40.0)


func _spawn_child(cfg: Dictionary) -> void:
	cfg["p1c"] = 0
	enemies.append(cfg)


func _enemy_fire(e: Dictionary) -> void:
	## 敌机开火: 朝自机方向 2 连弹 (原作 0x40213F 的近似, 精确弹型待 RE)
	var dx: float = player.x - e.x
	var dy: float = player.y - e.y
	var l := sqrt(dx * dx + dy * dy)
	if l <= 0.0:
		return
	bullets_e.append({
		"x": e.x, "y": e.y, "vx": dx / l * 3.5, "vy": dy / l * 3.5,
		"kind": 1, "w": 6.0, "h": 6.0, "ch": "狙",
	})


func _collide() -> void:
	for b in bullets_p.duplicate():
		var hit := false
		for e in enemies:
			if absf(b.x - e.x) < e.w * 0.5 + b.w and absf(b.y - e.y) < e.h * 0.5 + b.h:
				hit = true
				e.hp -= 1
				if e.hp <= 0:
					enemies.erase(e)
					score += 100
				break
		if hit:
			bullets_p.erase(b)
	for b in bullets_e:
		if absf(b.x - player.x) < 8.0 and absf(b.y - player.y) < 8.0:
			bullets_e.erase(b)
			_events.append("death")
			player_lives -= 1
			if player_lives <= 0:
				mode = "gameover"
				frame = 0
				audio.stop_bgm()
			else:
				player.x = 370.0
				player.y = 240.0


func _unhandled_input(ev: InputEvent) -> void:
	if ev.is_action_pressed("ui_pause"):
		paused = not paused
	if ev is InputEventKey and ev.pressed and ev.keycode == KEY_F1:
		print("sfx=", audio.toggle_sfx())
	if ev is InputEventKey and ev.pressed and ev.keycode == KEY_F2:
		print("bgm=", audio.toggle_bgm())
	if ev is InputEventKey and ev.pressed and ev.keycode == KEY_PRINT:
		get_viewport().get_texture().get_image().save_png("res://pscr%04d.png" % (frame % 10000))
	if ev is InputEventKey and ev.pressed and ev.keycode == KEY_ESCAPE:
		get_tree().quit()


# ------------------------------------------------------------ 渲染
func _draw() -> void:
	if mode == "title":
		draw_rect(Rect2(0, 0, W, H), Color(0.02, 0.03, 0.1))
		draw_string(hud_font, Vector2(180, 200), "撃破伝 REMAKE", HORIZONTAL_ALIGNMENT_LEFT, -1, 48, Color(0.9, 0.9, 1.0))
		draw_string(hud_font, Vector2(200, 260), "GEKIHADEN v1.06", HORIZONTAL_ALIGNMENT_LEFT, -1, 18, Color(0.6, 0.7, 0.9))
		if frame / 30 % 2 == 0:
			draw_string(hud_font, Vector2(205, 330), "PRESS C / CLICK", HORIZONTAL_ALIGNMENT_LEFT, -1, 20, Color(1, 1, 0.5))
		return
	if mode == "gameover":
		draw_rect(Rect2(0, 0, W, H), Color(0.1, 0, 0, 0.6))
		draw_string(hud_font, Vector2(240, 230), "遊戯終了", HORIZONTAL_ALIGNMENT_LEFT, -1, 40, Color(1, 0.4, 0.4))
		draw_string(hud_font, Vector2(220, 280), "SCORE %d" % score, HORIZONTAL_ALIGNMENT_LEFT, -1, 22, Color.WHITE)
		return
	if bg_img and not logic_only:
		if bg_tex == null or frame % 2 == 0:
			bg_tex = ImageTexture.create_from_image(bg_img)
		draw_texture_rect(bg_tex, Rect2(0, 0, W, H), false)
	if _laser_target != null and _laser_target.x > player.x:
		draw_line(Vector2(player.x, player.y), Vector2(_laser_target.x, _laser_target.y),
			Color(1, 0.3, 0.3, 0.8), 2.0)
		_laser_target = null
	if kanji_font != null:
		# 敌机: 真实字形位图 (bm_sX 切片), 按类型选字形, 无则回退 draw_string
		for e in enemies:
			var drawn := false
			if enemy_texes.size() > 0:
				var gi: int = (e.type * 7 + e.param) % enemy_texes.size()
				var t: Texture2D = enemy_texes[gi]
				var sz: float = 96.0 if e.type == 0x29 else 48.0
				draw_texture_rect(t, Rect2(e.x - sz * 0.5, e.y - sz * 0.5, sz, sz), false)
				drawn = true
			if not drawn:
				var ch: String = ENEMY_KANJI.get(e.type, "賊")
				var col := Color(0.95, 0.55, 0.2) if e.type == 0x23 else Color(0.9, 0.3, 0.25)
				draw_string(kanji_font, Vector2(e.x - 12, e.y + 10), ch,
					HORIZONTAL_ALIGNMENT_LEFT, -1, 24, col)
		# 敌弹: 小字 (白/浅蓝)
		for b in bullets_e:
			var drawn_b := false
			if bullet_texes.size() > 0:
				var gi_b: int = (b.kind * 13 + int(b.x)) % bullet_texes.size()
				var t_b: Texture2D = bullet_texes[gi_b]
				var sz_b := 12.0
				draw_texture_rect(t_b, Rect2(b.x - sz_b * 0.5, b.y - sz_b * 0.5, sz_b, sz_b), false)
				drawn_b = true
			if not drawn_b:
				var bc: String = b.get("ch", BULLET_E_KANJI[b.kind & 3])
				draw_string(kanji_font, Vector2(b.x - 5, b.y + 4), bc,
					HORIZONTAL_ALIGNMENT_LEFT, -1, 10, Color(0.92, 0.92, 1.0))
		# 自弹: 黄色小字向右
		for b in bullets_p:
			draw_string(kanji_font, Vector2(b.x - 5, b.y + 4), BULLET_P_KANJI,
				HORIZONTAL_ALIGNMENT_LEFT, -1, 10, Color(1, 0.95, 0.4))
		# 自机: 战机字形位图 (击/凛/汉, bm_otc 切片)
		if ship_tex != null:
			var ss := 36.0
			draw_texture_rect(ship_tex, Rect2(player.x - ss * 0.5, player.y - ss * 0.5, ss, ss), false)
		else:
			draw_string(kanji_font, Vector2(player.x - 13, player.y + 11), PLAYER_KANJI,
				HORIZONTAL_ALIGNMENT_LEFT, -1, 26, Color(0.35, 1.0, 0.45))
	else:
		var enemy_col := Color(0.78, 0.47, 0.24)
		for e in enemies:
			draw_rect(Rect2(e.x - e.w * 0.5, e.y - e.h * 0.5, e.w, e.h), enemy_col, false, 2.0)
		for b in bullets_e:
			draw_rect(Rect2(b.x - 3, b.y - 3, 6, 6), Color.WHITE)
		for b in bullets_p:
			draw_rect(Rect2(b.x - 3, b.y - 3, 6, 6), Color(1, 1, .47))
		draw_rect(Rect2(player.x - 8, player.y - 8, 16, 16), Color(.47, 1, .47), false, 2.0)
	# 左侧竖排 HUD (原作: 雷/炸/連 状态栏)
	if kanji_font != null and not logic_only:
		for i in HUD_LEFT.size():
			draw_string(kanji_font, Vector2(6, 60 + i * 44), HUD_LEFT[i],
				HORIZONTAL_ALIGNMENT_LEFT, -1, 28, Color(0.75, 0.55, 0.95))
		draw_string(kanji_font, Vector2(6, 40), "%d" % player_lives,
			HORIZONTAL_ALIGNMENT_LEFT, -1, 18, Color(0.9, 0.9, 1.0))
	if hud_font and not logic_only:
		draw_string(hud_font, Vector2(200, 16), "SCORE %06d" % score,
			HORIZONTAL_ALIGNMENT_LEFT, -1, 13, Color(1, 0.95, 0.5))

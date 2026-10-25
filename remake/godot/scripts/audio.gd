extends Node
## 音频: BGM (assets/bgm/bgm_NN.wav 占位合成) + 音效 (assets/sfx/se_NN.wav).

var bgm_player: AudioStreamPlayer
var sfx_players: Array = []
var bgm_enabled := true
var sfx_enabled := true


func _ready() -> void:
	bgm_player = AudioStreamPlayer.new()
	add_child(bgm_player)


func play_bgm(idx: int) -> void:
	if not bgm_enabled:
		return
	var path := "res://assets/bgm/bgm_%02d.ogg" % idx
	if not ResourceLoader.exists(path):
		return
	bgm_player.stream = load(path)
	bgm_player.play()


func stop_bgm() -> void:
	bgm_player.stop()


func se(idx: int, volume_db: float = 0.0) -> void:
	if not sfx_enabled:
		return
	var path := "res://assets/sfx/se_%02d.wav" % idx
	if not ResourceLoader.exists(path):
		return
	for p in sfx_players:
		if not p.playing:
			p.stream = load(path)
			p.volume_db = volume_db
			p.play()
			return
	var p := AudioStreamPlayer.new()
	p.stream = load(path)
	p.volume_db = volume_db
	add_child(p)
	sfx_players.append(p)
	if sfx_players.size() > 16:
		var old = sfx_players.pop_front()
		old.queue_free()
	p.play()


func toggle_bgm() -> bool:
	bgm_enabled = not bgm_enabled
	if not bgm_enabled:
		stop_bgm()
	return bgm_enabled


func toggle_sfx() -> bool:
	sfx_enabled = not sfx_enabled
	return sfx_enabled

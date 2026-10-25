"""撃破伝重制版主循环: 640x480 8bpp 调色板渲染, 60fps 固定步长.

横版弹幕射击: 自机初始 (370,240), 敌机从右侧入场 (脚本 OP02 (x,y,type,flag)),
弹幕由 12 通道发射器 (state/delta 积分器) 产生.
"""
from __future__ import annotations

import os
import random
import sys

import pygame

from . import assets
from .scriptvm import EmitterBank, StageRunner, fp

W, H = 640, 480
FPS = 60
FIXED = 1 << 16

# resource id: 45=Opng 46-52=Stg1-7 53-59=Clr 66-72=Stg1-7(二周)
STAGE_STREAMS = {1: 46, 2: 47, 3: 48, 4: 49, 5: 50, 6: 51, 7: 52}


class Entity:
    __slots__ = ("x", "y", "vx", "vy", "hp", "kind", "type", "w", "h", "alive", "age")

    def __init__(self, x, y, vx=0, vy=0, hp=1, kind=0, type_=0, w=16, h=16):
        self.x, self.y = x, y
        self.vx, self.vy = vx, vy
        self.hp, self.kind, self.type = hp, kind, type_
        self.w, self.h = w, h
        self.alive = True
        self.age = 0


class Game:
    def __init__(self, stage: int = 1, second_loop: bool = False, seed: int = 1):
        self.res = assets.Resources.load()
        self.pal = assets.load_palette()
        self.rng = random.Random(seed)
        self.emitters = EmitterBank(self.rng)
        self.runner = StageRunner(self.res, self.emitters, STAGE_STREAMS[stage], [])
        self.stage = stage
        self.frame = 0
        self.score = 0
        self.shots_fired = 0
        self.shots_hit = 0

        self.player = Entity(370 * FIXED, 240 * FIXED, w=12, h=12)
        self.player_lives = 3
        self.player_shot_cooldown = 0

        self.enemies: list[Entity] = []
        self.bullets_e: list[Entity] = []   # 敌弹 (16.16)
        self.bullets_p: list[Entity] = []   # 自机弹

        self.bg = assets.load_stage_bg(self.res, stage - 1, second_loop)
        self.events: list[str] = []

    # ------------------------------------------------------------ 每帧
    def tick(self, keys, mouse_pos, buttons):
        self.frame += 1
        self.runner.tick()
        self._consume_cmds()
        self.emitters.update()
        self._collect_bullets()
        self._move_player(keys, mouse_pos)
        self._player_fire(buttons)
        self._update_entities()
        self._collide()

    def _consume_cmds(self):
        q = self.runner.vm.q
        for cmd in q[2][:]:
            # OP02 (x, y, type<<24|p, flag): 敌机生成
            self.enemies.append(Entity(
                cmd.a * FIXED, cmd.b * FIXED,
                vx=-2 * FIXED, vy=0,
                hp=8, type_=cmd.c >> 24, kind=cmd.c & 0xFFFFFF, w=24, h=24,
            ))
        for cmd in q[1][:]:
            if (cmd.c & 0xFF) == 1 and cmd.a in (370,):  # 开场定位
                self.player.x, self.player.y = cmd.a * FIXED, cmd.b * FIXED
        for op in (1, 2, 3, 4, 5):
            q[op].clear()
        if self.runner.vm.transition is not None:
            self.events.append(f"transition:{self.runner.vm.transition}")
            self.runner.vm.transition = None

    def _collect_bullets(self):
        for b in self.emitters.fired:
            vx = b["vx"]
            vy = b["vy"]
            self.bullets_e.append(Entity(
                b["x"], b["y"], vx=vx, vy=vy, kind=b["kind"], w=6, h=6,
            ))
        self.emitters.fired.clear()

    def _move_player(self, keys, mouse_pos):
        p = self.player
        if mouse_pos:
            p.x = mouse_pos[0] * FIXED
            p.y = mouse_pos[1] * FIXED
        speed = 5 * FIXED
        if keys[pygame.K_LEFT]:
            p.x -= speed
        if keys[pygame.K_RIGHT]:
            p.x += speed
        if keys[pygame.K_UP]:
            p.y -= speed
        if keys[pygame.K_DOWN]:
            p.y += speed
        p.x = max(8 * FIXED, min((W - 8) * FIXED, p.x))
        p.y = max(8 * FIXED, min((H - 8) * FIXED, p.y))

    def _player_fire(self, buttons):
        if self.player_shot_cooldown > 0:
            self.player_shot_cooldown -= 1
        if buttons[0] and self.player_shot_cooldown == 0:
            p = self.player
            self.bullets_p.append(Entity(p.x, p.y - 10 * FIXED, vx=0, vy=-12 * FIXED, w=4, h=10))
            self.player_shot_cooldown = 5
            self.shots_fired += 1

    def _update_entities(self):
        p = self.player
        for e in self.enemies:
            e.x += e.vx
            e.y += e.vy
            e.age += 1
            if e.x < -60 * FIXED:
                e.alive = False
        for b in self.bullets_e + self.bullets_p:
            b.x += b.vx
            b.y += b.vy
            b.age += 1
            if not (-40 * FIXED <= b.x <= (W + 40) * FIXED and -40 * FIXED <= b.y <= (H + 40) * FIXED):
                b.alive = False
        self.enemies = [e for e in self.enemies if e.alive]
        self.bullets_e = [b for b in self.bullets_e if b.alive]
        self.bullets_p = [b for b in self.bullets_p if b.alive]

    def _collide(self):
        px, py = self.player.x, self.player.y
        # 自机弹 x 敌机
        for b in list(self.bullets_p):
            for e in self.enemies:
                if (abs(b.x - e.x) < (e.w // 2 + b.w) * FIXED and
                        abs(b.y - e.y) < (e.h // 2 + b.h) * FIXED):
                    b.alive = False
                    e.hp -= 1
                    self.shots_hit += 1
                    if e.hp <= 0:
                        e.alive = False
                        self.score += 100
                    break
        # 敌弹 x 自机
        for b in self.bullets_e:
            if (abs(b.x - px) < 8 * FIXED and abs(b.y - py) < 8 * FIXED):
                b.alive = False
                self.events.append("death")


# ---------------------------------------------------------------- 渲染

PALETTE_REMAP = {  # 调试配色: 敌机/弹按类型着色 (待替换为真实精灵)


}


def render(screen: pygame.Surface, game: Game, font=None):
    bg = pygame.image.frombuffer(game.bg, (W, H), "P")
    bg.set_palette([(r, g, b) for r, g, b in game.pal])
    screen.blit(bg, (0, 0))

    def rect(x16, y16, w, h, color):
        pygame.draw.rect(screen, color, (x16 // FIXED - w // 2, y16 // FIXED - h // 2, w, h))

    for e in game.enemies:
        color = (200, 120, 60) if e.type == 0x23 else (120, 160, 220)
        rect(e.x, e.y, e.w, e.h, color)
    for b in game.bullets_e:
        color = [(255, 255, 255), (255, 180, 180), (180, 255, 180), (180, 180, 255)][b.kind & 3]
        rect(b.x, b.y, b.w, b.h, color)
    for b in game.bullets_p:
        rect(b.x, b.y, b.w, b.h, (255, 255, 120))
    rect(game.player.x, game.player.y, 14, 14, (120, 255, 120))

    if font:
        s = font.render(f"frame {game.frame}  score {game.score}  E{len(game.enemies)} B{len(game.bullets_e)}", False, (255, 255, 255))
        screen.blit(s, (4, 4))


def main(stage: int = 1, frames: int | None = None, headless: bool = False, outdir: str = "."):
    pygame.init()
    if not headless:
        pygame.display.set_mode((W, H))
    screen = pygame.Surface((W, H), depth=8)
    pal_rgb = [(r, g, b) for r, g, b in assets.load_palette()]
    screen.set_palette(pal_rgb)
    font = pygame.font.SysFont(None, 16) if not headless else None
    game = Game(stage=stage)
    clock = pygame.time.Clock()
    frame = 0
    running = True
    while running:
        for ev in pygame.event.get():
            if ev.type == pygame.QUIT or (ev.type == pygame.KEYDOWN and ev.key == pygame.K_ESCAPE):
                running = False
            elif ev.type == pygame.KEYDOWN and ev.key == pygame.K_PRINTSCREEN:
                pygame.image.save(screen, os.path.join(outdir, f"pscr{frame % 10000:04d}.bmp"))
        keys = pygame.key.get_pressed()
        buttons = (pygame.mouse.get_pressed()[0], pygame.mouse.get_pressed()[2])
        mouse = pygame.mouse.get_pos() if not headless else None
        game.tick(keys, mouse, buttons)
        render(screen, game, font)
        if not headless:
            pygame.display.get_surface().blit(screen, (0, 0))
            pygame.display.flip()
            clock.tick(FPS)
        frame += 1
        if frames is not None and frame >= frames:
            break
    pygame.image.save(screen, os.path.join(outdir, f"remake_frame{frame}.png"))
    print(f"frames={frame} score={game.score} enemies_spawned_total={len(game.events)}")
    return game


if __name__ == "__main__":
    args = sys.argv[1:]
    stage = int(args[0]) if args else 1
    frames = int(args[1]) if len(args) > 1 else None
    headless = "--headless" in args
    main(stage, frames, headless)

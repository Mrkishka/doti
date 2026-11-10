import http.server
import socketserver
import urllib.parse
import random
import math
import webbrowser

# --- КРИПТОГРАФИЧЕСКИЕ ФУНКЦИИ ---
def fast_pow(base, exp, mod):
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result

def extended_gcd(a, b):
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t

def is_prime(n, k=5):
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0: return False
    for _ in range(k):
        a = random.randint(2, n - 2)
        if fast_pow(a, n - 1, n) != 1: return False
    return True

def random_prime(bits=32):
    while True:
        c = random.getrandbits(bits)
        if c < 3: continue
        if c % 2 == 0: c += 1
        if is_prime(c): return c

# --- ЛОГИКА ИГРЫ ---
SUITS = ["♠", "♥", "♦", "♣"]
RANKS = ["2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K", "A"]

def card_to_str(num):
    idx = num - 2
    return f"{RANKS[idx % 13]}{SUITS[idx // 13]}"

class MentalPokerGame:
    def __init__(self, num_players):
        self.num_players = num_players
        # Генерируем модуль n = p * q
        p = random_prime(32)
        q = random_prime(32)
        while p == q: q = random_prime(32)
        self.n = p * q
        self.phi = (p - 1) * (q - 1)
        
        # Генерируем ключи для каждого игрока
        self.player_keys = []
        for _ in range(num_players):
            while True:
                e = random.randint(2, self.phi - 1)
                if math.gcd(e, self.phi) == 1:
                    _, d, _ = extended_gcd(e, self.phi)
                    self.player_keys.append((e, d % self.phi))
                    break
                    
        self.deck = list(range(2, 54)) # 52 карты
        self.encrypted_deck = None
        self.player_hands = [[] for _ in range(num_players)]
        self.community = []

    def shuffle_and_encrypt(self):
        deck = self.deck[:]
        for e, _ in self.player_keys:
            deck = [fast_pow(card, e, self.n) for card in deck]
            random.shuffle(deck)
        self.encrypted_deck = deck

    def draw_for_player(self, player_idx):
        card = self.encrypted_deck.pop(0)
        # Снимаем замки всех игроков, КРОМЕ целевого
        for i, (_, d) in enumerate(self.player_keys):
            if i != player_idx:
                card = fast_pow(card, d, self.n)
        # Целевой игрок снимает свой замок
        _, d_target = self.player_keys[player_idx]
        return fast_pow(card, d_target, self.n)

    def draw_community(self):
        card = self.encrypted_deck.pop(0)
        # Снимают замки ВСЕ игроки
        for _, d in self.player_keys:
            card = fast_pow(card, d, self.n)
        return card

# --- ВЕБ-СЕРВЕР ---
game = None

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global game
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        action = query.get('action', [None])[0]

        if parsed.path == '/':
            if action == 'start':
                players = int(query.get('players', ['2'])[0])
                players = max(2, min(8, players))
                game = MentalPokerGame(players)
                game.shuffle_and_encrypt()
            elif action == 'deal_hole' and game:
                for i in range(game.num_players):
                    while len(game.player_hands[i]) < 2:
                        c = game.draw_for_player(i)
                        game.player_hands[i].append(card_to_str(c))
            elif action == 'deal_flop' and game and len(game.community) == 0:
                for _ in range(3):
                    game.community.append(card_to_str(game.draw_community()))
            elif action == 'deal_turn' and game and len(game.community) == 3:
                game.community.append(card_to_str(game.draw_community()))
            elif action == 'deal_river' and game and len(game.community) == 4:
                game.community.append(card_to_str(game.draw_community()))
            elif action == 'reset':
                game = None

            self.render_page()
        else:
            self.send_error(404)

    def render_page(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Cache-Control', 'no-store') # Отключаем кэш
        self.end_headers()

        html = """
        <!DOCTYPE html><html><head><meta charset="utf-8"><title>Ментальный покер</title>
        <style>
            body { font-family: Arial, sans-serif; background: #0f3a22; color: white; padding: 20px; text-align: center; }
            .container { max-width: 900px; margin: auto; }
            .panel { background: rgba(0,0,0,0.5); padding: 20px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 4px 8px rgba(0,0,0,0.5); }
            .btn { display: inline-block; padding: 10px 15px; background: #ffd700; color: #000; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 5px; }
            .btn:hover { background: #fff; }
            .btn.disabled { background: #555; color: #888; pointer-events: none; }
            .card { display: inline-block; background: white; color: black; font-weight: bold; padding: 10px 15px; margin: 5px; border-radius: 5px; font-size: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.5); }
            .card.red { color: #d00; }
            .player-box { display: inline-block; border: 1px solid #444; padding: 15px; margin: 10px; border-radius: 8px; background: rgba(255,255,255,0.1); min-width: 180px; vertical-align: top; }
            .player-box h3 { margin: 0 0 10px 0; color: #ffd700; }
            .hidden-cards { color: #aaa; font-style: italic; }
        </style></head><body><div class="container">
        <h1>🃏 Ментальный покер (Техасский холдем)</h1>
        """

        if not game:
            html += """
            <div class="panel">
                <h2>Создать новую игру</h2>
                <form method="GET" action="/">
                    <input type="hidden" name="action" value="start">
                    <label>Игроков (2-8): <input type="number" name="players" value="2" min="2" max="8"></label>
                    <button type="submit" class="btn">Начать</button>
                </form>
                <p><i>После старта колода будет зашифрована и перемешана всеми игроками.</i></p>
            </div>
            """
        else:
            # Панель управления
            html += f"<div class='panel'><h2>Стол</h2><p>Осталось карт в колоде: <b>{len(game.encrypted_deck)}</b></p>"
            
            if game.player_hands[0] and len(game.player_hands[0]) >= 2:
                html += "<span class='btn disabled'>Карманные карты разданы</span>"
            else:
                html += "<a href='/?action=deal_hole' class='btn'>Раздать карманные карты (по 2)</a>"
                
            c_len = len(game.community)
            if c_len == 0:
                html += "<a href='/?action=deal_flop' class='btn'>Открыть Флоп (3 карты)</a>"
            elif c_len == 3:
                html += "<a href='/?action=deal_turn' class='btn'>Открыть Тёрн (1 карта)</a>"
            elif c_len == 4:
                html += "<a href='/?action=deal_river' class='btn'>Открыть Ривер (1 карта)</a>"
            elif c_len == 5:
                html += "<span class='btn disabled'>Все общие карты открыты</span>"
                
            html += "<br><br><a href='/?action=reset' class='btn' style='background:#d32f2f; color:white;'>Сбросить игру</a></div>"

            # Игроки
            html += "<div class='panel'><h2>Карманные карты</h2>"
            for i, hand in enumerate(game.player_hands):
                html += f"<div class='player-box'><h3>Игрок {i+1}</h3>"
                if not hand:
                    html += "<span class='hidden-cards'>карт нет</span>"
                else:
                    for c in hand:
                        rc = 'red' if '♥' in c or '♦' in c else ''
                        html += f"<span class='card {rc}'>{c}</span>"
                html += "</div>"
            html += "</div>"

            # Общие карты
            html += "<div class='panel'><h2>Общие карты на столе</h2>"
            if not game.community:
                html += "<span class='hidden-cards'>пока нет</span>"
            else:
                for c in game.community:
                    rc = 'red' if '♥' in c or '♦' in c else ''
                    html += f"<span class='card {rc}'>{c}</span>"
            html += "</div>"

        html += "</div></body></html>"
        self.wfile.write(html.encode('utf-8'))

class ThreadingServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

def main():
    # Порт 0 означает: пусть система сама найдет свободный порт
    with ThreadingServer(("", 0), Handler) as httpd:
        port = httpd.server_address[1]
        url = f"http://localhost:{port}"
        print("=" * 60)
        print(f"  СЕРВЕР ЗАПУЩЕН: {url}")
        print("  Открой этот адрес в браузере Windows.")
        print("  Если страница выглядит сломанной - нажми Ctrl+F5.")
        print("  Остановить сервер: Ctrl+C")
        print("=" * 60)
        
        try:
            webbrowser.open(url)
        except:
            pass

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nСервер остановлен.")

if __name__ == "__main__":
    main()
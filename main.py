# pyinstaller --clean --onefile --windowed --name SudoSudo --workpath "build_chromium" --distpath "dist_chromium" --icon="sudosudo.ico" --add-data "ip_things\sudosudo\ia.env;." --collect-all webview --collect-all pythonnet --collect-all clr_loader --hidden-import=webview.platforms.edgechromium --hidden-import=pythonnet "ip_things\sudosudo\main.py"
# A chave deve ficar em ia.env ou OPENROUTER_API_KEY, nunca no codigo-fonte.

import socket
import random
import ssl
import threading
import json
import struct
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime

try:
    from ia_service import IAService
except ImportError:
    IAService = None

try:
    import webview
except ImportError:
    webview = None


PORTAS_INTERESSANTES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    8080: "HTTP-alt", 25565: "Minecraft",
}

PORTAS_WEB = {80, 443, 8080}

CATEGORIAS = {
    "SQL": [3306],
    "Minecraft": [25565],
    "RDP": [3389],
    "SSH": [22],
    "FTP": [21],
    "Web": [80, 443, 8080],
    "Outros": [23, 25, 53, 110, 143, 445],
}

# reverse: porta -> categoria
PORTA_CATEGORIA = {p: cat for cat, portas in CATEGORIAS.items() for p in portas}
# DB


# ---------- FUNÇÕES DE SCAN ----------
def varint(n):
    out = b""
    while True:
        b_ = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b_ | 0x80])
        else:
            out += bytes([b_])
            return out


def info_minecraft(ip, porta=25565):
    try:
        with socket.create_connection((ip, porta), timeout=3) as s:
            s.settimeout(3)
            host = ip.encode()
            corpo = varint(754) + varint(len(host)) + host + \
                    struct.pack(">H", porta) + varint(1)
            pacote = varint(len(corpo) + 1) + b"\x00" + corpo
            s.sendall(pacote)
            s.sendall(b"\x01\x00")
            resp = s.recv(4096)
            ini = resp.find(b"{")
            if ini >= 0:
                info = json.loads(resp[ini:].decode("utf-8", "ignore"))
                d = info.get("description", {})
                motd = d.get("text", str(d)) if isinstance(d, dict) else str(d)
                ver = info.get("version", {}).get("name", "?")
                online = info.get("players", {}).get("online", "?")
                return f"Minecraft {ver} | jogadores: {online} | {motd[:40]}"
    except Exception:
        return None


def banner_mysql(ip, porta=3306):
    try:
        with socket.create_connection((ip, porta), timeout=3) as s:
            s.settimeout(3)
            dados = s.recv(128)
            if len(dados) > 5:
                ver = dados[4:dados.find(b"\x00", 4)].decode("utf-8", "ignore")
                return f"MySQL {ver}"
    except Exception:
        return None


def classifica_corpo(corpo):
    baixo = corpo.lower().strip()
    if not baixo:
        return "resposta vazia (health check?)"
    if baixo.startswith("{") or baixo.startswith("["):
        return f"JSON: {baixo[:60]}"
    if baixo.startswith("<?xml") or baixo.startswith("<wsdl"):
        return f"XML/SOAP: {baixo[:60]}"
    if "react" in baixo or "__next" in baixo or "ng-app" in baixo:
        return "SPA (app React/Next/Angular)"
    return f"HTML sem título ({len(corpo)} bytes)"


def testa_porta(ip, porta, timeout=1.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, porta)) == 0
    except OSError:
        return False


def info_cert(ip, porta=443):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, porta), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as s:
                cert = s.getpeercert(binary_form=True)
        import OpenSSL
        x509 = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_ASN1, cert)
        nomes = []
        for i in range(x509.get_extension_count()):
            ext = x509.get_extension(i)
            if "subjectAltName" in str(ext.get_short_name()):
                nomes = [n.strip() for n in str(ext).split(",")]
        cn = dict(x509.get_subject().get_components()).get(b"CN", b"")
        dom = nomes[0] if nomes else cn.decode(errors="ignore")
        return f"cert: {dom}"
    except ModuleNotFoundError:
        return None
    except Exception:
        return None


def testa_http(ip, porta):
    esquema = "https" if porta == 443 else "http"
    url = f"{esquema}://{ip}:{porta}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=3, context=ctx)
        status, corpo = resp.status, resp.read(4096).decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        try:
            corpo = e.read(4096).decode("utf-8", "ignore")
        except Exception:
            corpo = ""
        status = e.code
    except Exception:
        return None

    titulo = ""
    low = corpo.lower()
    if "<title>" in low and "</title>" in low:
        ini = low.index("<title>") + 7
        fim = low.index("</title>", ini)
        titulo = corpo[ini:fim].strip()[:50]

    return f"{status} {titulo or classifica_corpo(corpo)}"


def escaneia_ip(ip):
    achados = []
    for porta, nome in PORTAS_INTERESSANTES.items():
        if testa_porta(ip, porta):
            extra = ""
            if porta == 443:
                cert = info_cert(ip, porta)
                if cert:
                    extra += f" [{cert}]"
            if porta in PORTAS_WEB:
                info = testa_http(ip, porta)
                if info:
                    extra += f" -> {info}"
            if porta == 25565:
                mc = info_minecraft(ip, porta)
                if mc:
                    extra += f" -> {mc}"
            if porta == 3306:
                b = banner_mysql(ip, porta)
                if b:
                    extra += f" -> {b}"
            achados.append(f"{porta}({nome}){extra}")
    return ip, achados


def gerar_ips(quantidade, prefixo="internet"):
    ips = set()
    while len(ips) < quantidade:
        if prefixo.startswith("local "):
            partes = [parte for parte in prefixo.split(maxsplit=1)[1].split(".") if parte]
            while len(partes) < 3:
                partes.append(str(random.randint(0, 254)))
            ip = ".".join(partes[:3] + [str(random.randint(1, 254))])
        else:
            a = random.choice([171, 250])
            b = random.randint(9, 250)
            c = random.randint(1, 254)
            ip = f"172.{a}.{b}.{c}"
        ips.add(ip)
    return list(ips)


# ---------- SCORE ----------
PORTAS_SENSIVEIS = {3389: 30, 445: 30, 3306: 25, 23: 25, 21: 15, 22: 15, 25: 10}
PALAVRAS_PERIGOSAS = ["login", "sign in", "admin", "painel", "dashboard", "prtg"]
PALAVRAS_RUIDO = ["azure container app", "azure web app", "welcome to nginx",
                  "iis windows server", "not found", "canary", "unavailable"]


def pontua(achados):
    texto = " | ".join(achados).lower()
    pontos = 0
    for porta, peso in PORTAS_SENSIVEIS.items():
        if f"{porta}(" in texto:
            pontos += peso
    if any(p in texto for p in PALAVRAS_PERIGOSAS):
        pontos += 20
    if "spa" in texto or "xml/soap" in texto:
        pontos += 10
    if "json:" in texto and "session" in texto:
        pontos += 25
    elif "json:" in texto:
        pontos += 12
    if any(r in texto for r in PALAVRAS_RUIDO):
        pontos -= 15
    if "resposta vazia" in texto or "sem título" in texto:
        pontos -= 5
    if "80(http" in texto or "443(https" in texto or "8080(" in texto:
        pontos += 5

    if pontos >= 25: return "🔴", pontos
    if pontos >= 12: return "🟡", pontos
    if pontos >= 5:  return "🟢", pontos
    return "⚪", pontos


# ---------- INTERFACE WEB LOCAL ----------
ARQUIVO_HISTORICO = "achados.json"


def carregar_historico():
    if os.path.exists(ARQUIVO_HISTORICO):
        try:
            with open(ARQUIVO_HISTORICO, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def salvar_historico(lista):
    with open(ARQUIVO_HISTORICO, "w", encoding="utf-8") as f:
        json.dump(lista, f, ensure_ascii=False, indent=2)


# O HTML foi externo para o arquivo index.html (veja abaixo)
with open("index.html", "r", encoding="utf-8") as f:
    HTML = f.read()


class ScannerApp:
    def __init__(self):
        self.historico = carregar_historico()
        self.ia = IAService() if IAService else None
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.executor = None
        self.running = False
        self.closing = False
        self.status = "idle"
        self.progress = 0
        self.total = 0
        self.lines = []
        self.output_log = []
        self.counts = {"red": 0, "yellow": 0, "green": 0}

    def add_line(self, texto, classe=""):
        with self.lock:
            self.lines.append({"text": texto, "class": classe})
            self.lines = self.lines[-200:]
            self.output_log.append(texto)
            self.output_log = self.output_log[-500:]

    def output_atual(self):
        with self.lock:
            return "\n".join(self.output_log)

    def snapshot(self):
        with self.lock:
            lines, self.lines = self.lines, []
            return {**self.counts, "saved": len(self.historico), "running": self.running,
                    "label": self.status, "progress": self.progress, "total": self.total,
                    "lines": lines}

    def iniciar(self, dados):
        if self.running:
            raise ValueError("Já existe uma execução em andamento")
        if self.closing:
            raise ValueError("O aplicativo está sendo encerrado")
        try:
            quantidade = int(dados.get("quantity", 0))
        except (TypeError, ValueError):
            raise ValueError("Quantidade inválida")
        if not 1 <= quantidade <= 10000:
            raise ValueError("A quantidade deve estar entre 1 e 10000")
        categorias = [c for c in dados.get("categories", []) if c in CATEGORIAS]
        if not categorias:
            raise ValueError("Selecione pelo menos uma categoria")
        alvo = str(dados.get("target", "")).strip() or "internet"
        with self.lock:
            self.stop_event.clear()
            self.running, self.status = True, "..."
            self.progress, self.total = 0, quantidade
            self.counts = {"red": 0, "yellow": 0, "green": 0}
        threading.Thread(target=self.executar, args=(quantidade, alvo, categorias), daemon=True).start()

    def executar(self, quantidade, alvo, categorias):
        ips = gerar_ips(quantidade, alvo)
        portas_alvo = {p for cat in categorias for p in CATEGORIAS[cat]}
        self.add_line(f"[>] {len(ips)} IPs | categorias: {', '.join(categorias)}")
        resultados = []
        pool = ThreadPoolExecutor(max_workers=100)
        self.executor = pool
        try:
            futuros = {pool.submit(self.scan_filtrado, ip, portas_alvo): ip for ip in ips}
            for i, futuro in enumerate(as_completed(futuros), 1):
                if self.stop_event.is_set():
                    break
                ip, achados = futuro.result()
                if achados:
                    resultados.append((ip, achados))
                with self.lock:
                    self.progress = i
                    self.status = f"scanning {i}/{len(ips)}"
        finally:
            for futuro in futuros:
                futuro.cancel()
            pool.shutdown(wait=False, cancel_futures=True)
            self.executor = None
        if self.stop_event.is_set():
            with self.lock:
                self.running = False
                self.status = "wrapping up"
            return
        pontuados = []
        for ip, achados in resultados:
            emoji, pontos = pontua(achados)
            pontuados.append((pontos, ip, achados))
        pontuados.sort(key=lambda x: x[1], reverse=True)
        for pontos, ip, achados in pontuados:
            emoji, _ = pontua(achados)
            marcador = {"!>!": "!>!", ">": ">", ">>": ">>", "-": "-"}.get(emoji, "-")
            self.add_line(f"{marcador} [{pontos:3}] {ip} -> {', '.join(achados)}")
            self.historico.append({"data": datetime.now().strftime("%Y-%m-%d %H:%M"), "ip": ip,
                                   "score": pontos, "emoji": emoji, "servicos": achados})
        with self.lock:
            self.counts = {"red": sum(p[0] == "!>!" for p in pontuados),
                           "yellow": sum(p[0] == ">" for p in pontuados),
                           "green": sum(p[0] == ">>" for p in pontuados)}
            self.running, self.status = False, "done"
        salvar_historico(self.historico)
        self.add_line(f"--> !>!{self.counts['red']} >{self.counts['yellow']} >>{self.counts['green']} | histórico: {len(self.historico)}")

    def scan_filtrado(self, ip, portas_alvo):
        achados = []
        for porta in portas_alvo:
            if self.stop_event.is_set():
                break
            nome = PORTAS_INTERESSANTES.get(porta, "?")
            if testa_porta(ip, porta):
                extra = ""
                if porta == 443:
                    cert = info_cert(ip, porta)
                    if cert: extra += f" [{cert}]"
                if porta in PORTAS_WEB:
                    info = testa_http(ip, porta)
                    if info: extra += f" -> {info}"
                if porta == 25565:
                    mc = info_minecraft(ip, porta)
                    if mc: extra += f" -> {mc}"
                if porta == 3306:
                    b = banner_mysql(ip, porta)
                    if b: extra += f" -> {b}"
                achados.append(f"{porta}({nome}){extra}")
        return ip, achados

    def encerrar(self):
        with self.lock:
            if self.closing:
                return
            self.closing = True
            self.status = "wrapping up..."
        self.stop_event.set()
        if self.executor is not None:
            self.executor.shutdown(wait=False, cancel_futures=True)

class LocalHandler(BaseHTTPRequestHandler):
    app = None

    def log_message(self, *_):
        pass

    def json_response(self, payload, code=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            body = HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/status":
            self.json_response(self.app.snapshot())
        elif self.path == "/api/history":
            self.json_response(self.app.historico)
        elif self.path == "/api/ai/status":
            self.json_response(self.app.ia.status() if self.app.ia else {"configured": False})
        else:
            self.send_error(404)

    def do_POST(self):
        tamanho = int(self.headers.get("Content-Length", 0))
        try:
            dados = json.loads(self.rfile.read(tamanho) or b"{}") if tamanho else {}
            if self.path == "/api/start":
                self.app.iniciar(dados)
                self.json_response({"ok": True})
            elif self.path == "/api/save":
                salvar_historico(self.app.historico)
                self.json_response({"message": f"💾 {len(self.app.historico)} achados salvos"})
            elif self.path == "/api/ai/settings":
                if not self.app.ia:
                    raise RuntimeError("Servico de IA indisponivel")
                self.app.ia.salvar_chave(dados.get("token", ""))
                self.json_response({"ok": True, "configured": bool(self.app.ia.api_key)})
            elif self.path in ("/api/ai/chat", "/api/ai/classify"):
                if not self.app.ia:
                    raise RuntimeError("Servico de IA indisponivel")
                output = str(dados.get("output", ""))
                if self.path.endswith("/classify"):
                    resposta = self.app.ia.classificar(output)
                else:
                    imagem = dados.get("image")
                    if imagem:
                        if not isinstance(imagem, str) or len(imagem) > 8 * 1024 * 1024:
                            raise ValueError("A imagem deve ter no maximo 8 MB")
                        permitidos = ("data:image/png;base64,", "data:image/jpeg;base64,",
                                      "data:image/webp;base64,", "data:image/gif;base64,")
                        if not imagem.startswith(permitidos):
                            raise ValueError("Formato de imagem nao suportado")
                    resposta = self.app.ia.conversar(
                        str(dados.get("question", "")), output, imagem
                    )
                self.json_response({"answer": resposta})
            else:
                self.send_error(404)
        except (ValueError, RuntimeError) as erro:
            self.json_response({"error": str(erro)}, 400)


def iniciar_servidor():
    app = ScannerApp()
    for porta in range(8765, 8775):
        try:
            servidor = ThreadingHTTPServer(("127.0.0.1", porta), LocalHandler)
            break
        except OSError:
            continue
    else:
        raise OSError("Nenhuma porta local disponível entre 8765 e 8774")
    LocalHandler.app = app
    url = f"http://127.0.0.1:{porta}"
    print(f"SudoSudo disponível em {url}")
    if webview is not None:
        threading.Thread(target=servidor.serve_forever, daemon=True).start()
        janela = webview.create_window("SudoSudo", url, width=1200, height=760,
                                      min_size=(900, 600), resizable=True)

        def fechar():
            app.encerrar()
            servidor.shutdown()
            servidor.server_close()

        janela.events.closed += fechar
        try:
            webview.start(gui="edgechromium")
        finally:
            app.encerrar()
            servidor.shutdown()
            servidor.server_close()
    else:
        threading.Timer(0.35, lambda: webbrowser.open(url)).start()
        try:
            servidor.serve_forever()
        except KeyboardInterrupt:
            app.encerrar()
            servidor.shutdown()
            servidor.server_close()


if __name__ == "__main__":
    iniciar_servidor()
##pyinstaller --clean --onefile --windowed --name SudoSudo --workpath "build_chromium" --distpath "dist_chromium" --icon="sudosudo.ico" --add-data "ip_things\sudosudo\ia.env;." --collect-all webview --collect-all pythonnet --collect-all clr_loader --hidden-import=webview.platforms.edgechromium --hidden-import=pythonnet "ip_things\sudosudo\main.py"
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

#.termi

HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SudoSudo</title>
<style>
:root{--bg:#000000;--panel:#000000;--panel2:#000000;--panel3:#000000;--line:#ffffff;--text:#ffffff;--muted:#ffffff;--blue:#ffffff;--green:#ffffff;--yellow:#ffffff;--red:#ffffff;--font:"Trebuchet MS","Segoe UI",sans-serif;--mono:"JetBrains Mono",Consolas,"Courier New",monospace}
*{box-sizing:border-box}html,body{width:100%;height:100%;margin:0;padding:0;overflow:hidden;background:var(--bg);color:var(--text);font-family:var(--font)}
.app{display:grid!important;position:relative!important;grid-template-columns:280px minmax(0,1fr)!important;grid-template-rows:60px minmax(0,1fr)!important;width:100vw!important;height:100vh!important;overflow:hidden!important}
.top{grid-column:1/3!important;grid-row:1!important;background:#000000!important;border-bottom:1px solid var(--line)!important;display:flex!important;align-items:center!important;padding:0 24px!important;gap:16px!important}
.brand{font-size:16px;font-weight:700;color:#ffffff;letter-spacing:.5px}.brand b{color:#ffffff;text-decoration:underline}.crumb{font-size:11px;color:var(--muted);border-left:1px solid var(--line);padding-left:16px;text-transform:uppercase;letter-spacing:1px}
.top #server{font-size:11px;font-family:var(--mono);color:#ffffff;border:1px solid #ffffff;padding:4px 12px;border-radius:20px;background:#000000;margin-left:auto}
.side{grid-column:1!important;grid-row:2!important;background:var(--panel)!important;border-right:1px solid var(--line)!important;padding:24px 20px!important;overflow-y:auto!important}
.label{color:var(--muted);font-size:11px;font-weight:600;margin:16px 0 8px;text-transform:uppercase;letter-spacing:1px}.side .label:first-child{margin-top:0}
.field{width:100%;background:#000000;border:1px solid var(--line);border-radius:6px;color:var(--text);padding:10px 12px;font-family:var(--font);font-size:13px;margin-bottom:12px;transition:border-color .15s,box-shadow .15s}.field:focus{outline:0;border-color:#ffffff;box-shadow:0 0 0 2px #ffffff}
.checks{display:grid!important;grid-template-columns:1fr 1fr!important;gap:8px!important;padding:12px!important;background:#000000!important;border:1px solid var(--line)!important;border-radius:6px!important;margin-bottom:16px!important}.checks label{cursor:pointer;color:var(--text);font-size:12px;display:flex;align-items:center}.checks input{accent-color:#ffffff;margin-right:8px}
.btn{border:1px solid var(--line);background:#000000;color:var(--text);padding:10px 14px;border-radius:6px;font-family:var(--font);font-size:13px;font-weight:500;cursor:pointer;transition:background .15s,border-color .15s}.btn:hover{background:#ffffff;color:#000000}
.primary{width:100%;background:#ffffff;border-color:#ffffff;color:#000000;font-weight:600}.primary:hover{background:#000000;color:#ffffff}.primary:disabled{opacity:.5;cursor:wait}
.workspace{grid-column:2!important;grid-row:2!important;padding:24px 32px!important;display:flex!important;flex-direction:column!important;overflow:hidden!important;min-width:0}.tabs{display:flex;gap:6px;border-bottom:1px solid var(--line);margin-bottom:20px}.tab{border:0;border-bottom:2px solid transparent;background:transparent;color:var(--muted);padding:11px 16px;font:600 12px var(--font);letter-spacing:.5px;cursor:pointer}.tab:hover,.tab.active{color:#ffffff;border-bottom-color:#ffffff}.tab-panel{display:none;min-height:0;flex:1;flex-direction:column}.tab-panel.active{display:flex}.panel-heading{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:16px}.panel-heading h1{margin:0;color:#ffffff;font-size:22px;letter-spacing:.2px}.panel-heading p{margin:5px 0 0;color:var(--muted);font-size:12px}

/* AI Layout Modernizado */
.ai-layout{display:grid;grid-template-columns:minmax(0,1fr) 250px;gap:20px;min-height:0;flex:1}
.ai-card{background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:0;display:flex;flex-direction:column;min-height:0;overflow:hidden}
.ai-header-bar{display:flex;align-items:center;justify-content:space-between;padding:12px 18px;background:var(--panel);border-bottom:1px solid var(--line)}
.ai-header-title{font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:1px;display:flex;align-items:center;gap:8px}
.ai-header-title::before{content:"";display:inline-block;width:8px;height:8px;border-radius:50%;background:#ffffff}
.ai-chat{flex:1;padding:20px;overflow-y:auto;display:flex;flex-direction:column;gap:16px;background:#000000}

/* Chat Messages Formatting */
.chat-msg{display:flex;flex-direction:column;max-width:85%;animation:fadeIn .2s ease-in-out}
.chat-msg.user{align-self:flex-end;align-items:flex-end}
.chat-msg.ai{align-self:flex-start;align-items:flex-start}
.chat-bubble{padding:12px 16px;border-radius:10px;font-size:13px;line-height:1.6;position:relative}
.chat-msg.user .chat-bubble{background:#ffffff;border:1px solid #ffffff;color:#000000;border-bottom-right-radius:2px}
.chat-msg.ai .chat-bubble{background:#000000;border:1px solid #ffffff;color:#ffffff;border-bottom-left-radius:2px}
.chat-meta{font-size:10px;color:var(--muted);margin-bottom:4px;text-transform:uppercase;letter-spacing:.5px}

.ai-input-container{padding:16px;background:var(--panel);border-top:1px solid var(--line);display:flex;flex-direction:column;gap:12px}
.ai-input-wrapper{position:relative;display:flex;align-items:center}
.ai-input{width:100%;height:52px;resize:none;background:#000000;border:1px solid var(--line);border-radius:8px;color:var(--text);padding:14px 16px;font:13px var(--font);transition:border-color .15s}
.ai-input:focus{outline:0;border-color:#ffffff;box-shadow:0 0 0 2px #ffffff}
.ai-controls{display:flex;align-items:center;justify-content:space-between;gap:10px}.image-tools{display:flex;align-items:center;gap:10px;min-height:28px}.image-tools label{color:var(--muted);font-size:11px;cursor:pointer;text-decoration:underline}.image-tools input{display:none}.image-preview{display:none;align-items:center;gap:8px;color:var(--text);font-size:11px}.image-preview.visible{display:flex}.image-preview img{width:34px;height:34px;object-fit:cover;border-radius:5px;border:1px solid var(--line)}.image-remove{border:0;background:transparent;color:#ffffff;cursor:pointer;font-size:16px}

.ai-sidebar{display:flex;flex-direction:column;gap:16px}
.ai-sidebar .stat-card{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:16px}
.ai-sidebar .stat-card .title{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;font-weight:600}
.ai-sidebar .stat-card .value{font-size:20px;font-weight:700;color:#ffffff;margin-top:6px;font-family:var(--mono)}

.memory-note{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:16px;color:var(--muted);font-size:12px;line-height:1.5}
.memory-note strong{color:#ffffff;display:block;margin-bottom:6px;font-size:11px;text-transform:uppercase;letter-spacing:1px}

/* Typography Helpers */
.md p{margin:0 0 8px}.md p:last-child{margin:0}
.md code{background:#000000;color:#ffffff;border:1px solid #ffffff;border-radius:4px;padding:2px 6px;font:12px var(--mono)}
.md pre{background:#000000;border:1px solid var(--line);border-radius:6px;padding:12px;margin:8px 0;overflow-x:auto}
.md ul{margin:6px 0;padding-left:18px}.md li{margin:3px 0}
@keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}

.toolbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px}.title{font-size:20px;font-weight:600;color:#ffffff}.status{color:#ffffff;font-size:13px;font-family:var(--mono)}.status.busy{color:#ffffff;text-decoration:underline}
.grid{display:grid!important;grid-template-columns:repeat(4,minmax(0,1fr))!important;gap:16px!important;margin-bottom:20px!important}.stat{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:16px 20px;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}.stat b{display:block;font-size:24px;font-weight:600;color:#ffffff;margin-top:6px;font-family:var(--mono)}
.terminal{background:var(--panel2);border:1px solid var(--line);border-radius:8px;flex:1 1 auto;padding:16px;white-space:pre-wrap;line-height:1.6;font-family:var(--mono);font-size:13px;overflow-y:auto;user-select:text;cursor:text}
.history-card{background:#000000;border:1px solid var(--line);border-radius:10px;padding:16px}
.history-list{overflow-y:auto;display:flex;flex-direction:column;gap:8px}.history-item{padding:12px;border:1px solid var(--line);border-radius:7px;background:var(--panel2);font:12px var(--mono)}
.line{padding:2px 0;word-break:break-all}.danger{color:#ffffff;font-weight:bold}.cool{color:#ffffff;font-style:italic}.site{color:#ffffff;text-decoration:underline}
.small{font-size:12px;color:var(--muted);line-height:1.5;border-top:1px solid var(--line);padding-top:16px;margin-top:24px}
.settings-card{max-width:620px;background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:20px}.settings-card h2{margin:0 0 8px;color:#ffffff;font-size:16px}.settings-card p{margin:0 0 18px;color:var(--muted);font-size:12px;line-height:1.5}.settings-actions{display:flex;align-items:center;gap:12px}.settings-message{font-size:12px;color:var(--muted)}
@media(max-width:760px){.app{display:block!important;height:auto!important;min-height:100vh!important;overflow:auto!important}.top{height:60px!important}.side,.workspace{display:block!important;width:100%!important;height:auto!important}.workspace{padding:20px!important}.terminal{height:400px!important}.grid{grid-template-columns:repeat(2,1fr)!important}.tabs{overflow-x:auto}.ai-layout{grid-template-columns:1fr}.ai-sidebar{display:grid;grid-template-columns:1fr 1fr}.ai-sidebar .memory-note{grid-column:1/-1}}
</style></head><body><div class="app"><header class="top"><div class="brand"><b>sudo</b>sudo</div><div class="crumb">v0.0.7</div><div style="margin-left:auto" id="server">● LOCAL SOCKET</div></header>
<aside class="side"><div class="label">Scan Configuration</div><input id="amount" class="field" type="number" min="1" max="10000" value="200" title="IP Quantity"><input id="target" class="field" value="local 192.168." title="Target Range"><div class="label">Categories</div><div class="checks" id="checks"></div><button id="start" class="btn primary">Start Scan</button><div class="label" style="margin-top:24px">Workspace</div><button id="save" class="btn" style="width:100%">Save Results</button><p class="small">Authorized networks and systems only.</p></aside>
<main class="workspace"><nav class="tabs" aria-label="Workspace"><button class="tab active" data-tab="output">Output</button><button class="tab" data-tab="history">History</button><button class="tab" data-tab="ai">AI Analyst</button></nav><section id="tab-output" class="tab-panel active"><div class="toolbar"><div class="title"><span style="color:var(--muted)">// output</span></div><div id="status" class="status">● Idle</div></div><div class="grid"><div class="stat">Danger<b id="red">0</b></div><div class="stat">Cool<b id="yellow">0</b></div><div class="stat">Site<b id="green">0</b></div><div class="stat">Saved<b id="saved">0</b></div></div><div id="terminal" class="terminal"><div class="line">SudoSudo local scanner v0.0.7</div><div class="line">Ready to scan authorized targets.</div></div></section><section id="tab-history" class="tab-panel"><div class="panel-heading"><div><h1>Scan History</h1><p>Saved findings from previous runs.</p></div><button id="refresh-history" class="btn">Refresh</button></div><div class="history-card history-list" id="history-list"><div class="memory-note">No history loaded.</div></div></section><section id="tab-ai" class="tab-panel"><div class="panel-heading"><div><h1>AI Intelligence Console</h1><p>Real-time threat assessment and telemetry parsing.</p></div><div id="ai-state" class="status">Checking status...</div></div><div class="ai-layout"><div class="ai-card"><div class="ai-header-bar"><div class="ai-header-title">Console Session</div><button id="clear-ai" class="btn" style="padding:4px 10px;font-size:11px">Clear Workspace</button></div><div id="ai-chat" class="ai-chat"><div class="chat-msg ai"><div class="chat-meta" id="ai-chat-model-name">AI Assistant</div><div class="chat-bubble md">Ready to process scan telemetry. Ask a query or trigger automated classification.</div></div></div><div class="ai-input-container"><div class="ai-input-wrapper"><textarea id="ai-input" class="ai-input" placeholder="Query scan findings or analysis..."></textarea></div><div class="image-tools"><label for="ai-image">Attach image</label><input id="ai-image" type="file" accept="image/png,image/jpeg,image/webp,image/gif"><div id="image-preview" class="image-preview"><img id="image-thumb" alt="Selected image"><span id="image-name"></span><button id="image-remove" class="image-remove" type="button" title="Remove image">x</button></div></div><div class="ai-controls"><button id="classify-ai" class="btn">Classify Active Output</button><button id="ask-ai" class="btn primary" style="width:auto;padding:8px 20px">Send Query</button></div></div></div><aside class="ai-sidebar"><div class="stat-card"><div class="title">Active Model</div><div class="value" id="ai-model">-</div></div><div class="stat-card"><div class="title">Context Memory</div><div class="value" id="ai-memory">0</div></div><div class="memory-note"><strong>Session Memory</strong>Engine retains historical classification vectors and logs across active sessions.</div><button id="ai-output" class="btn primary" style="background:var(--panel2);border-color:var(--line);color:var(--text)">View Output Terminal</button></aside></div></section></main></div>
<script>
var currentModelName = 'AI Assistant';
var cats=['SQL','Minecraft','RDP','SSH','FTP','Web','Other'];
var terminal=document.getElementById('terminal');var timer=null;
var selectedImage=null;
var checks=document.getElementById('checks');var checkHtml='';
for(var i=0;i<cats.length;i++){checkHtml+='<label><input type="checkbox" value="'+cats[i]+'" '+(i<4?'checked':'')+'>'+cats[i]+'</label>';}
checks.innerHTML=checkHtml;
function line(text,cls){var el=document.createElement('div');var autoClass=cls||'';if(!cls&&typeof text==='string'){var prefix=text.replace(/^\s+/, '');if(prefix.indexOf('!>!')===0){autoClass='danger';}else if(prefix.indexOf('>>')===0){autoClass='site';}else if(prefix.indexOf('>')===0){autoClass='cool';}}el.className='line '+autoClass;el.textContent=text;terminal.appendChild(el);terminal.scrollTop=terminal.scrollHeight;}
function request(url,method,data,done){var xhr=new XMLHttpRequest();xhr.open(method||'GET',url,true);xhr.setRequestHeader('Content-Type','application/json');xhr.onreadystatechange=function(){if(xhr.readyState===4){var result;try{result=JSON.parse(xhr.responseText);}catch(e){result={error:'Invalid response from server'};}done(xhr.status,result);}};xhr.send(data?JSON.stringify(data):null);}
function setStats(s){var keys=['red','yellow','green','saved'];for(var i=0;i<keys.length;i++){document.getElementById(keys[i]).textContent=s[keys[i]]||0;}}
var aiChat=document.getElementById('ai-chat');
function escapeHtml(text){return String(text).replace(/[&<>"']/g,function(char){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char];});}
function inlineMarkdown(text){var safe=escapeHtml(text);safe=safe.replace(/`([^`]+)`/g,'<code>$1</code>').replace(/\*\*(.*?)\*\*/g,'<strong>$1</strong>').replace(/__(.*?)__/g,'<strong>$1</strong>').replace(/\*([^*\n]+)\*/g,'<em>$1</em>').replace(/_([^_\n]+)_/g,'<em>$1</em>');return safe;}
function markdown(text){var linhas=String(text||'').replace(/\r/g,'').split('\n');var html='';var paragrafo=[];var lista=[];var codigo=[];var emCodigo=false;function fecharParagrafo(){if(paragrafo.length){html+='<p>'+paragrafo.map(inlineMarkdown).join('<br>')+'</p>';paragrafo=[];}}function fecharLista(){if(lista.length){html+='<ul>'+lista.map(function(item){return '<li>'+inlineMarkdown(item)+'</li>';}).join('')+'</ul>';lista=[];}}function fecharCodigo(){if(emCodigo){html+='<pre><code>'+escapeHtml(codigo.join('\n'))+'</code></pre>';codigo=[];emCodigo=false;}}for(var i=0;i<linhas.length;i++){var linha=linhas[i];if(/^\s*```/.test(linha)){fecharParagrafo();fecharLista();if(emCodigo){fecharCodigo();}else{emCodigo=true;}continue;}if(emCodigo){codigo.push(linha);continue;}if(/^\s*$/.test(linha)){fecharParagrafo();fecharLista();continue;}var titulo=linha.match(/^\s*(#{1,3})\s+(.+)$/);if(titulo){fecharParagrafo();fecharLista();var nivel=titulo[1].length;html+='<h'+nivel+'>'+inlineMarkdown(titulo[2])+'</h'+nivel+'>';continue;}var item=linha.match(/^\s*[-*+]\s+(.+)$/);if(item){fecharParagrafo();lista.push(item[1]);continue;}var citacao=linha.match(/^\s*>\s?(.+)$/);if(citacao){fecharParagrafo();fecharLista();html+='<blockquote>'+inlineMarkdown(citacao[1])+'</blockquote>';continue;}fecharLista();paragrafo.push(linha);}fecharParagrafo();fecharLista();fecharCodigo();return html;}
function aiAppendMsg(role, text, cls, image){
  var msgEl=document.createElement('div');
  msgEl.className='chat-msg '+role;
  var metaEl=document.createElement('div');
  metaEl.className='chat-meta';
  metaEl.textContent=role==='user'?'Operator':currentModelName;
  var bubbleEl=document.createElement('div');
  bubbleEl.className='chat-bubble md '+(cls||'');
  bubbleEl.innerHTML=markdown(text);
    if(image){var imageEl=document.createElement('img');imageEl.src=image;imageEl.alt='Attached image';imageEl.style.cssText='display:block;max-width:220px;max-height:150px;object-fit:contain;border-radius:6px;margin-bottom:8px;border:1px solid var(--line)';bubbleEl.insertBefore(imageEl,bubbleEl.firstChild);}
  msgEl.appendChild(metaEl);
  msgEl.appendChild(bubbleEl);
  aiChat.appendChild(msgEl);
  aiChat.scrollTop=aiChat.scrollHeight;
}
function setImage(dataUrl,name){selectedImage=dataUrl;document.getElementById('image-thumb').src=dataUrl;document.getElementById('image-name').textContent=name;document.getElementById('image-preview').classList.add('visible');}
document.getElementById('ai-image').onchange=function(){var arquivo=this.files[0];if(!arquivo){return;}if(arquivo.size>8*1024*1024){this.value='';aiAppendMsg('ai','Image must be smaller than 8 MB.','danger');return;}var leitor=new FileReader();leitor.onload=function(){setImage(leitor.result,arquivo.name);};leitor.readAsDataURL(arquivo);};
document.getElementById('image-remove').onclick=function(){selectedImage=null;document.getElementById('ai-image').value='';document.getElementById('image-preview').classList.remove('visible');};
function aiRequest(path,payload){
  aiAppendMsg('ai','Processing telemetry...','cool');
  request(path,'POST',payload,function(status,result){
    var temp=aiChat.querySelectorAll('.chat-msg.ai');
    if(temp.length){temp[temp.length-1].remove();}
    aiAppendMsg('ai', status===200?result.answer:(result.error||'Request execution failed'), status===200?'':'danger');
  });
}
function currentOutput(){var linhas=terminal.getElementsByClassName('line');var saida='';for(var i=0;i<linhas.length;i++){saida+=linhas[i].textContent+'\n';}return saida;}
document.querySelector('.tabs').insertAdjacentHTML('beforeend','<button class="tab" data-tab="settings">Settings</button>');
document.querySelector('.workspace').insertAdjacentHTML('beforeend','<section id="tab-settings" class="tab-panel"><div class="panel-heading"><div><h1>Settings</h1><p>Update the AI connection without rebuilding the application.</p></div></div><div class="settings-card"><h2>OpenRouter API token</h2><p>The token is stored in ia.env beside the executable. It is never displayed after saving.</p><input id="ai-token" class="field" type="password" autocomplete="off" placeholder="sk-or-v1-..."><div class="settings-actions"><button id="save-ai-token" class="btn primary" style="width:auto">Save Token</button><span id="settings-message" class="settings-message"></span></div></div></section>');
document.getElementById('save-ai-token').onclick=function(){var token=document.getElementById('ai-token').value.trim();request('/api/ai/settings','POST',{token:token},function(status,result){var message=document.getElementById('settings-message');message.textContent=status===200?'Token saved.':'Save failed: '+(result.error||'unknown error');if(status===200){document.getElementById('ai-token').value='';document.getElementById('ai-state').textContent=token?'AI Ready':'API key missing';}});};
var tabs=document.getElementsByClassName('tab');for(var t=0;t<tabs.length;t++){tabs[t].onclick=function(){for(var j=0;j<tabs.length;j++){tabs[j].classList.remove('active');document.getElementById('tab-'+tabs[j].getAttribute('data-tab')).classList.remove('active');}this.classList.add('active');document.getElementById('tab-'+this.getAttribute('data-tab')).classList.add('active');if(this.getAttribute('data-tab')==='history'){carregarHistorico();}};}
document.getElementById('clear-ai').onclick=function(){
  aiChat.innerHTML='<div class="chat-msg ai"><div class="chat-meta">'+escapeHtml(currentModelName)+'</div><div class="chat-bubble md">Console cleared. Active telemetry buffer remains attached.</div></div>';
};
document.getElementById('ai-output').onclick=function(){document.querySelector('[data-tab="output"]').click();};
document.getElementById('classify-ai').onclick=function(){aiRequest('/api/ai/classify',{output:currentOutput()});};
document.getElementById('ask-ai').onclick=function(){
  var pergunta=document.getElementById('ai-input').value.trim();
    if(!pergunta && !selectedImage){return;}
    aiAppendMsg('user', pergunta||'Analyze the attached image.', '', selectedImage);
  document.getElementById('ai-input').value='';
    aiRequest('/api/ai/chat',{question:pergunta,output:currentOutput(),image:selectedImage});
    selectedImage=null;document.getElementById('ai-image').value='';document.getElementById('image-preview').classList.remove('visible');
};
function carregarHistorico(){request('/api/history','GET',null,function(status,result){var lista=document.getElementById('history-list');if(status!==200||!result.length){lista.innerHTML='<div class="memory-note">No history logs saved.</div>';return;}lista.innerHTML='';var inicio=Math.max(0,result.length-100);for(var i=result.length-1;i>=inicio;i--){var item=result[i];var el=document.createElement('div');el.className='history-item';el.textContent=(item.emoji||'')+'  '+item.data+' | '+item.ip+' | score '+item.score+'\n'+(item.servicos||[]).join(', ');lista.appendChild(el);}});}
request('/api/ai/status','GET',null,function(status,result){if(status!==200){document.getElementById('ai-state').textContent='AI unavailable';return;}document.getElementById('ai-state').textContent=result.configured?'● AI Ready':'● API key missing';if(result.model){currentModelName=result.model;document.getElementById('ai-model').textContent=result.model;var initMeta=document.getElementById('ai-chat-model-name');if(initMeta){initMeta.textContent=result.model;}}else{document.getElementById('ai-model').textContent='-';}document.getElementById('ai-memory').textContent=result.memories||0;});
function poll(){request('/api/status','GET',null,function(status,s){if(status!==200){line('Backend unavailable','danger');return;}document.getElementById('status').textContent='● '+s.label;document.getElementById('status').className='status '+(s.running?'busy':'');setStats(s);for(var i=0;i<s.lines.length;i++){line(s.lines[i].text,s.lines[i].class);}if(!s.running){if(timer){clearInterval(timer);timer=null;}document.getElementById('start').disabled=false;}});}
document.getElementById('start').onclick=function(){var selected=[];var inputs=checks.getElementsByTagName('input');for(var i=0;i<inputs.length;i++){if(inputs[i].checked){selected.push(inputs[i].value);}}request('/api/start','POST',{quantity:parseInt(document.getElementById('amount').value,10),target:document.getElementById('target').value,categories:selected},function(status,result){if(status!==200){line(result.error||'Failed to start execution','danger');return;}terminal.innerHTML='';line('[>] Execution started');document.getElementById('start').disabled=true;timer=setInterval(poll,700);poll();});};
document.getElementById('save').onclick=function(){request('/api/save','POST',null,function(status,result){line(result.message||result.error,'site');poll();});};
document.getElementById('refresh-history').onclick=carregarHistorico;
poll();
</script></body></html>'''


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
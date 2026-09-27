import json
import os
import re
import sys
from pathlib import Path

import requests

from memoria import MemoriaSudoSudo


class IAService:
    def __init__(self):
        self.memoria = MemoriaSudoSudo()
        self.api_key = os.environ.get("OPENROUTER_API_KEY")
        self.env_path = self._config_path()
        self._carregar_chave()
        self.model = os.environ.get("SUDOSUDO_AI_MODEL", "z-ai/glm-5.3-flash")

    @staticmethod
    def _config_path():
        if getattr(sys, "frozen", False):
            return Path(sys.executable).resolve().parent / "ia.env"
        return Path(__file__).resolve().parent / "ia.env"

    def _carregar_chave(self):
        if self.api_key or not self.env_path.exists():
            return
        for linha in self.env_path.read_text(encoding="utf-8").splitlines():
            nome, separador, valor = linha.partition("=")
            if separador and nome.strip() == "OPENROUTER_API_KEY":
                self.api_key = valor.strip().strip('"')
                break

    def salvar_chave(self, api_key):
        api_key = str(api_key or "").strip()
        self.env_path.write_text(
            f"OPENROUTER_API_KEY={api_key}\n",
            encoding="utf-8",
        )
        self.api_key = api_key or None

    def caminho_configuracao(self):
        return str(self.env_path)

    @staticmethod
    def _memoria_pedida(texto):
        padrao = re.compile(
            r"(?:^|\b)(?:lembre(?:-se)?|lembrar|guarde|guardar|memorize|memorizar|"
            r"salve|salvar)\s*(?:que|de que|isso)?\s*[:,-]?\s*(.+)$",
            re.IGNORECASE,
        )
        resultado = padrao.search(str(texto).strip())
        if not resultado:
            return None
        fato = resultado.group(1).strip(" .!?\n\t")
        return fato or None

    @staticmethod
    def _consulta_memoria(texto):
        texto = str(texto).lower()
        return any(termo in texto for termo in (
            "o que você lembra", "o que voce lembra", "o que mandei lembrar",
            "o que mandei vc lembrar", "o que mandei voce lembrar",
            "o que pedi para lembrar", "o que pedi pra lembrar",
            "o que pedi vc lembrar", "minhas memórias", "minhas memorias",
            "lembra de mim", "memória", "memoria",
        ))

    def _pedir(self, mensagens):
        if not self.api_key:
            raise RuntimeError("OPENROUTER_API_KEY nao configurada")
        resposta = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "http://127.0.0.1",
                "X-Title": "SudoSudo",
            },
            json={"model": self.model, "messages": mensagens},
            timeout=45,
        )
        try:
            dados = resposta.json()
        except ValueError as erro:
            raise RuntimeError(f"Resposta invalida da IA ({resposta.status_code})") from erro
        if resposta.status_code >= 400:
            mensagem = dados.get("error", {}).get("message", "erro desconhecido")
            raise RuntimeError(f"OpenRouter {resposta.status_code}: {mensagem}")
        try:
            return dados["choices"][0]["message"]["content"].strip()
        except (KeyError, IndexError, TypeError) as erro:
            raise RuntimeError("A IA retornou uma resposta sem texto") from erro

    def conversar(self, pergunta, output="", imagem=None):
        fato = self._memoria_pedida(pergunta)
        if fato:
            salvo = self.memoria.adicionar(fato)
            estado = "foi salva" if salvo else "já estava salva"
            return f"Entendi. A informação {estado} na minha memória: {fato}"

        contexto = output[-12000:] if output else "Nenhum output do scanner fornecido."
        memoria_contexto = (
            self.memoria.contexto()
            if self._consulta_memoria(pergunta)
            else self.memoria.contexto(pergunta)
        )
        prompt = (
            "Voce e o analista local do SudoSudo. Responda na linguagem do usuario, de forma objetiva. "
            "Use somente o output fornecido como evidencia, diferencie fato de hipotese e "
            "nao fique perguntando sobre o output quando for a hora de voce examinar ele voce vai usar ele.\n\n"
            "nao ensine exploracao, credenciais ou acesso indevido.\n\n"
            "seja útil em qualquer aspecto como codico e etc...\n\n"
            "nao pergunte toda hora sobre o output, apena siga o fluxo da conversa.\n\n"
            f"{memoria_contexto}\n\n"
            f"OUTPUT DO SCANNER:\n{contexto}\n\nPERGUNTA:\n{pergunta}"
        )
        conteudo = [{"type": "text", "text": prompt}]
        if imagem:
            conteudo.append({"type": "image_url", "image_url": {"url": imagem}})
        resposta = self._pedir([
            {"role": "system", "content": "Analise defensiva de inventario e superficie exposta."},
            {"role": "user", "content": conteudo},
        ])
        self.memoria.adicionar(f"Pergunta: {pergunta}\nAnalise: {resposta[:1200]}")
        return resposta

    def classificar(self, output):
        contexto = output[-16000:] if output else "Nenhum resultado encontrado."
        resposta = self._pedir([
            {
                "role": "system",
                "content": (
                    "Classifique resultados de inventario de rede para uso autorizado. "
                    "Retorne um resumo curto com: prioridade (alta/media/baixa), evidencias, "
                    "falsos positivos provaveis e proxima verificacao defensiva. Nao invente dados."
                ),
            },
            {"role": "user", "content": f"OUTPUT:\n{contexto}"},
        ])
        self.memoria.adicionar(f"Classificacao de scan:\n{resposta[:1600]}")
        return resposta

    def status(self):
        return {
            "configured": bool(self.api_key),
            "model": self.model,
            "memories": len(self.memoria.buscar()),
        }

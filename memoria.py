import json
import os
import threading
import uuid
from pathlib import Path


class MemoriaSudoSudo:
    """Memoria semantica inspirada no MemoryManager do TEDIO."""

    def __init__(self, base_dir=None):
        self.base_dir = Path(base_dir or __file__).resolve().parent
        self.fallback_path = self.base_dir / "memoria_sudosudo.json"
        self.usuario = "sudosudo"
        self._lock = threading.Lock()
        self.collection = None
        try:
            import chromadb
            from chromadb.utils import embedding_functions

            cliente = chromadb.PersistentClient(path=str(self.base_dir / "chroma_data"))
            self.collection = cliente.get_or_create_collection(
                name="memorias_sudosudo",
                embedding_function=embedding_functions.DefaultEmbeddingFunction(),
            )
        except Exception:
            self.collection = None

    def _fallback(self):
        try:
            with self.fallback_path.open("r", encoding="utf-8") as arquivo:
                return json.load(arquivo)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _salvar_fallback(self, fatos):
        temporario = self.fallback_path.with_suffix(".tmp")
        with temporario.open("w", encoding="utf-8") as arquivo:
            json.dump(fatos, arquivo, ensure_ascii=False, indent=2)
        os.replace(temporario, self.fallback_path)

    def adicionar(self, texto):
        texto = str(texto).strip()
        if not texto:
            return False
        with self._lock:
            if self.collection is not None:
                existentes = self.collection.get(where={"usuario": self.usuario}).get("documents") or []
                if texto in existentes:
                    return False
                self.collection.add(
                    ids=[f"{self.usuario}:{uuid.uuid4().hex[:8]}"],
                    documents=[texto],
                    metadatas=[{"usuario": self.usuario}],
                )
                return True
            fatos = self._fallback()
            if texto in fatos:
                return False
            fatos.append(texto)
            self._salvar_fallback(fatos)
            return True

    def buscar(self, pergunta="", limite=8):
        pergunta = str(pergunta).strip()
        with self._lock:
            if self.collection is not None:
                if not pergunta:
                    return (self.collection.get(where={"usuario": self.usuario}).get("documents") or [])[-limite:]
                if self.collection.count() == 0:
                    return []
                resultado = self.collection.query(
                    query_texts=[pergunta],
                    n_results=limite,
                    where={"usuario": self.usuario},
                )
                return (resultado.get("documents") or [[]])[0]
            fatos = self._fallback()
            if not pergunta:
                return fatos[-limite:]
            termos = set(pergunta.lower().split())
            ranqueados = sorted(
                fatos,
                key=lambda fato: sum(termo in fato.lower() for termo in termos),
                reverse=True,
            )
            return [fato for fato in ranqueados if any(termo in fato.lower() for termo in termos)][:limite]

    def contexto(self, pergunta=""):
        fatos = self.buscar(pergunta)
        if not fatos:
            return "Nenhuma memoria previa relevante."
        return "Memorias previas:\n" + "\n".join(f"- {fato}" for fato in fatos)

# SudoSudo

Scanner de rede com interface grafica (webview local) que varre faixas de
endereco IP, testa portas de servico, coleta banners/certificados e classifica
os achados por pontuacao.

> **Aviso legal**
> Use esta ferramenta apenas em infraestrutura que voce administra ou sobre a
> qual tenha autorizacao formal e por escrito. Varredura ativa em redes de
> terceiros sem autorizacao pode configurar crime nos termos da Lei 12.737/2012
> (invasao de dispositivo informatico aileo) e violar a LGPD (Lei 14.155/2021).
> A responsabilidade e de quem opera a ferramenta.

## Requisitos

- Python 3.10 ou superior
- Windows (o binario usa `--windowed` com pywebview/Edge WebView2)

## Instalacao

```bash
git clone https://github.com/Nyco-Kalashnikov/SudoSudo.git
cd SudoSudo
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Configuracao

A chave da OpenRouter e **opcional** (usada apenas pela analise por IA).
Copie o arquivo de exemplo e preencha:

```bash
copy ia.env.example ia.env
```

```env
OPENROUTER_API_KEY=sk-or-v1-sua-chave-aqui
SUDOSUDO_AI_MODEL=z-ai/glm-5.3-flash
```

> O arquivo `ia.env` esta no `.gitignore` e **nao deve ser commitado**.
> O binario compilado tambem nao embute mais esse arquivo: a chave e
> resolvida em tempo de execucao.

## Uso

```bash
python main.py
```

A interface web e aberta localmente (a porta e escolhida entre 8765 e 8774,
a primeira livre).

## O que a ferramenta faz

- **Varredura de portas:** 22, 23, 80, 443, 445, 3306, 25565
- **Coleta de informacao:** banner MySQL, titulo HTTP, certificado TLS
- **Pontuacao:** cada achado e classificado e ordenado por exposicao
- **Historico:** os resultados sao persistidos para comparacao entre execucoes
- **Memoria e IA:** camada opcional (ChromaDB + OpenRouter) para'analise
  dos achados e consulta ao historico

## Compilando

Ver `compile.txt`. O comando usa PyInstaller e gera um executavel unico.
A chave da API **nao** e inclusa no binario.

## Estrutura

| Arquivo | Funcao |
|---|---|
| `main.py` | UI, scanner e pontuacao |
| `ia_service.py` | Integracao com OpenRouter |
| `memoria.py` | Memoria persistente (ChromaDB + fallback JSON) |
| `compile.txt` | Comando de build (PyInstaller) |
| `sudosudo.ico` | Icone |

## Licenca

Ver `LICENSE`.

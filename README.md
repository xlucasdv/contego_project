# Contego Threat Dashboard

Plataforma web para consulta de indicadores de ameaça (IP, domínio e hash) no AlienVault OTX e VirusTotal, com dashboard, histórico local e briefing em linguagem natural.

## Funcionalidades

- Consulta de IPv4/IPv6, domínios e hashes (MD5/SHA1/SHA256)
- Dashboard com nível de risco, veredito, pulses e dados adicionais
- Histórico local de consultas (SQLite)
- Briefing com OpenAI (opcional) ou heurística local
- Normalização de entrada (extrai o domínio de URLs)

## Como rodar

```bash
git clone https://github.com/xlucasdv/contego_project.git
cd contego_project
pip install -r requirements.txt
copy .env.example .env    # opcional; edite com suas chaves
python -m uvicorn app.main:app --reload
```

Abra http://127.0.0.1:8000 — docs interativas da API em `/docs`.

Sem chaves configuradas, funciona com OTX em modo público + briefing heurístico.

## Variáveis de ambiente

| Variável | Descrição |
|---|---|
| `OTX_API_KEY` | Chave do OTX (opcional) |
| `VIRUSTOTAL_API_KEY` | Chave do VirusTotal (obrigatória p/ essa fonte) |
| `DEFAULT_PROVIDER` | `otx` (padrão) ou `virustotal` |
| `OPENAI_API_KEY` | Habilita briefing com IA (opcional) |
| `OPENAI_MODEL` | Modelo do briefing (padrão `gpt-4o-mini`) |

## Endpoints

| Método | Caminho | Descrição |
|---|---|---|
| POST | `/api/lookup` | Consulta um indicador |
| GET | `/api/history` | Lista o histórico |
| GET | `/api/history/{id}` | Detalha uma consulta |

## Estrutura

```text
app/
├── main.py          # API e rotas
├── config.py        # Variáveis de ambiente
├── database.py      # Histórico SQLite
├── indicator.py     # Classificação/normalização
├── services/        # OTX, VirusTotal e briefing
└── static/          # Dashboard (HTML/CSS/JS)
```

## Tratamento de erros

400 indicador inválido · 404 não encontrado · 401 chave ausente · 429 rate limit · 502/500 rede/interno. Consultas com erro também são registradas no histórico.

## Decisões técnicas

- FastAPI + httpx assíncrono com timeouts
- Normalização das respostas dos provedores (frontend desacoplado)
- SQLite sem dependência externa
- Chaves só por variáveis de ambiente; `.gitignore` protege `.env` e o banco

## Teste rápido

`8.8.8.8` (risco baixo) vs. hash do WannaCry `ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa` (risco alto). Consultar é seguro; não execute o artefato.

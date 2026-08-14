@'
# Contego Threat Dashboard

Plataforma web para consulta de indicadores de ameaça (IP, domínio e hash) em fontes de threat intelligence, com dashboard e histórico local.

## Funcionalidades

- Consulta de IP, domínio e hash (MD5/SHA1/SHA256)
- Fontes: AlienVault OTX (padrão) e VirusTotal
- Dashboard com nível de risco, veredito e detalhes de reputação
- Histórico local de consultas (SQLite)
- Resumo em linguagem natural (OpenAI, se configurada; caso contrário, heurística local)

## Requisitos

- Python 3.10+

## Como rodar

1. Clone e entre na pasta:

```bash
git clone https://github.com/xlucasdv/contego_project.git
cd contego_project
# Referência: CLI, variáveis, API, banco e audit

Consulta rápida. Para o passo a passo veja [how-to-use.md](how-to-use.md); para a policy, [policy-reference.md](policy-reference.md).

## 1. Linha de comando (`omotai`)

### `omotai start`

Inicia o servidor MCP.

| Opção | Padrão | Descrição |
| --- | --- | --- |
| `--policy PATH` | obrigatória | Arquivo de policy YAML |
| `--audit PATH` | `runs/audit.jsonl` | Arquivo do audit JSONL |
| `--mode stdio\|sse` | `stdio` | Transporte. `sse` sobe MCP e dashboard na mesma porta |
| `--dashboard / --no-dashboard` | desligado | Com `stdio`, sobe **somente** o dashboard (o MCP não inicia). Em `sse` o dashboard sempre sobe |
| `--port N` | `8080` | Porta do dashboard e do MCP SSE |
| `--host ADDR` | `127.0.0.1` | Endereço de escuta. `0.0.0.0` serve a rede (e imprime um aviso) |

Toda subida cria as tabelas do banco se elas não existirem. No modo `sse`, o navegador e o login do runtime acontecem na subida do servidor (pode levar de 10 s a cerca de 1 minuto num container), e uma falha no login impede o servidor de subir.

### `omotai domain`

Gerencia a tabela de domínios (efeito na próxima ação do agente, sem reiniciar).

| Comando | Descrição |
| --- | --- |
| `omotai domain add ORIGEM --allow` ou `--deny` | Adiciona ou muda a ação de uma origem. A origem é normalizada (`HTTP://Portal.TEST:80/x` -> `http://portal.test`). Sai com código 1 se faltar a flag, se vierem as duas, ou se a origem não for `http(s)` |
| `omotai domain rm ORIGEM` | Remove a origem |
| `omotai domain list` | Lista id, origem, ação e data |

### `omotai secret`

Gerencia o cofre (valores em texto puro no banco, veja a seção 4).

| Comando | Descrição |
| --- | --- |
| `omotai secret add NOME VALOR` | Grava ou atualiza um segredo |
| `omotai secret rm NOME` | Remove |
| `omotai secret list` | Lista id, nome e data (nunca os valores) |

## 2. Variáveis de ambiente

| Variável | Onde | Descrição |
| --- | --- | --- |
| `OMOTAI_ADMIN_TOKEN` | dashboard | Token de admin (mínimo 16 caracteres). Sem ela, o runtime gera um e o imprime na subida. O compose exige a variável no `.env` |
| `OMOTAI_DB` | tudo | Caminho do banco SQLite (padrão `runs/omotai.db`, relativo ao diretório de trabalho). Use para isolar execuções ou apontar para um volume Docker |
| `OMOTAI_AGENT_KEY` | `start` (stdio) | Só atribuição: o runtime procura o nome do agente com essa chave no banco para o log. Não autentica |
| `OMOTAI_BROWSER` | runtime, testes | Executável do Chromium, se você não quiser o do Playwright |
| variáveis do login | policy | Os nomes vêm de `login.user_env` e `login.password_env` (nos exemplos, `OMOTAI_LOGIN_USER` e `OMOTAI_LOGIN_PASSWORD`) |

## 3. API HTTP do dashboard

Tudo sob `/api/*` exige o token de admin (header `Authorization: Bearer <token>` ou o cookie `omotai_admin` criado pelo login), exceto `POST /api/login`. Sem credencial válida a resposta é `401`. Se o app não tiver token configurado, nada passa. Os arquivos estáticos (a interface) são públicos.

| Método e rota | Corpo | Resposta |
| --- | --- | --- |
| `POST /api/login` | `{"token": "..."}` | `200` e cookie `omotai_admin` (`HttpOnly`, `SameSite=Strict`), ou `401` |
| `GET /api/me` | | `200` se autenticado |
| `GET /api/agents` | | Lista `{id, name, api_key (mascarada), created_at}` |
| `POST /api/agents` | `{"name": "..."}` | `{id, name, api_key}`: a chave completa aparece **só aqui** |
| `DELETE /api/agents/{id}` | | Remove o agente (a chave deixa de valer) |
| `GET /api/secrets` | | Lista `{id, key_name, created_at}`, sem valores |
| `POST /api/secrets` | `{"key_name", "secret_value"}` | `{id, key_name}` |
| `DELETE /api/secrets/{id}` | | Remove |
| `GET /api/approvals` | | Últimas 50: `{id, session_id, reason, status, created_at, source}` |
| `POST /api/approvals/{id}` | `{"status": "approved"\|"denied"}` | `200`; `400` se o status é inválido; `409` se a aprovação não está mais `pending` (já respondida ou expirada) |
| `GET /api/domains` | | `{domains: [{id, origin, action, created_at}], policy_origins: [...]}`; `policy_origins` (origens do arquivo) só vem preenchido quando o runtime roda no mesmo processo (modo `sse`) |
| `POST /api/domains` | `{"origin", "action": "allow"\|"deny"}` | `{id, origin, action}` com a origem normalizada; `400` se não for origem `http(s)`; origem já existente muda de ação |
| `DELETE /api/domains/{id}` | | `200` ou `404` |
| `GET /api/logs/stream` | | Fluxo SSE das linhas do audit. Lê `runs/audit.jsonl` do diretório de trabalho, independentemente de `--audit` |

O endpoint MCP (modo `sse`) é separado: `GET /mcp/sse` com `Authorization: Bearer <chave de agente>`; sem chave válida a resposta é `401`.

## 4. Banco SQLite

Arquivo `runs/omotai.db` (ou `OMOTAI_DB`), em modo WAL. As tabelas são criadas ou migradas na subida.

| Tabela | Colunas |
| --- | --- |
| `agents` | `id`, `name`, `api_key` (única), `created_at` |
| `secrets` | `id`, `key_name` (única), `secret_value` (**texto puro**), `created_at` |
| `domains` | `id`, `origin` (única), `action` (`allow` ou `deny`), `created_at` |
| `approvals` | `id`, `session_id`, `reason`, `status` (`pending`, `approved`, `denied`), `source` (`agent` = `ask_human`; `runtime` = confirmação imposta), `created_at` |
| `audit_logs` | `id`, `timestamp`, `agent_name`, `session_id`, `event`, `tool`, `url`, `verdict`, `rule`, `request_payload`, `response_payload` |

Observações:

- O cofre não é cifrado (cifragem planejada). Trate o arquivo como um arquivo de senhas.
- `audit_logs` é uma cópia consultável dos eventos; a versão à prova de adulteração é o JSONL com cadeia de hashes.
- O runtime só aceita o valor `approved` como aprovação; qualquer outro é tratado como negação.

## 5. Audit JSONL

Um objeto JSON por linha em `runs/audit.jsonl` (ou `--audit`). Todo registro tem `ts`, `prev` (hash do anterior) e `hash` (SHA-256 de `prev` + o registro). `omotai.runtime.audit.verify(caminho)` devolve `False` se algum registro foi editado ou removido. O arquivo é rotacionado ao chegar a 5 MiB (mantém até `.1` a `.5`) e a cadeia continua entre os arquivos.

| Evento | Campos principais | Quando |
| --- | --- | --- |
| `tool` | `tool`, `n` | Início de cada `navigate`, `back` ou `act` |
| `decision` | `tool`, `url` ou `ref`, `action`, `facts`, `verdict`, `rule` | Decisão de policy sobre navegar ou agir |
| `sanitization` | `tool`, `url` ou `ref`, `verdict`, `rule` | Entrada rejeitada antes da policy (`unsafe_scheme`, `unsafe_ref`) |
| `request` | `method`, `url`, `type`, `verdict`, `rule` | Cada request do navegador julgado por `page.route()` |
| `proxy_deny` | `method`, `url`, `rule` | Salto (inclusive redirect) barrado pelo proxy |
| `websocket` | `url`, `verdict`, `rule` | WebSocket negado |
| `login` | `ok`, `url` | Login do runtime na subida |
| `observe` | `url`, `snapshot_sha256` | Cada leitura de página (só o hash do conteúdo) |
| `confirmation_requested` | `approval_id`, `ref`, `facts` | O runtime pediu confirmação ao operador |
| `confirmation` | `approval_id`, `ref`, `verdict`, `rule` | Resultado: `confirmation_approved`, `confirmation_denied`, `confirmed_action_changed` ou `confirmation_budget_exhausted` |
| `domains_reloaded` | `added`, `removed` | A tabela de domínios mudou a lista efetiva de origens |
| `domains_reload` | `verdict`, `rule` | Falha ao ler a tabela (`domains_unreadable`) |
| `tool_execution` | `tool`, `request`, `response` (truncado em 1000 caracteres), `verdict` (`ALLOW`/`DENY`), `rule` | Resultado de cada tool MCP |
| `finish` | `answer` | Resposta final do agente |

O audit nunca contém a chave de agente nem valores do cofre: as chaves viram o **nome** do agente, e segredos são substituídos por `[redacted]`.

## 6. Arquivos e portas

| O quê | Padrão |
| --- | --- |
| Banco | `runs/omotai.db` |
| Audit | `runs/audit.jsonl` (+ `.1` a `.5`) |
| Dashboard e MCP (`--mode sse`) | `127.0.0.1:8080`; no compose, `8000` (`omotai-runtime`) e `8080` (`omotai-ui`) |
| Mock portal do `omotai/eval` | `http://localhost:8001` (visto do container: `host.docker.internal:8001`) |

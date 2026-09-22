# Guia de Configuração e Uso do MCP (Omotai Runtime)

Este documento detalha como instalar, configurar e utilizar o servidor MCP (Model Context Protocol) da Omotai, com foco nas funcionalidades de segurança, telemetria (Dashboard) e gestão de agentes (implementadas nas Opções A e B).

## 1. Instalação e Requisitos Iniciais

Para utilizar o servidor MCP Omotai localmente, certifique-se de ter o Python 3.10 ou superior instalado no seu sistema.

```bash
# Clone o repositório
git clone https://github.com/omotai/runtime.git
cd runtime

# Instale o pacote e suas dependências localmente
pip install -e .
```

Para ferramentas baseadas em navegação (ex: Playwright), instale também os navegadores obrigatórios:
```bash
playwright install chromium
```

## 2. Inicializando o Servidor MCP com a CLI

O `omotai/runtime` agora possui uma interface de linha de comando (`omotai`) moderna e ergonômica. 

Para subir o servidor com o Dashboard ativo (porta web para telemetria em tempo real):
```bash
omotai start --dashboard --port 8080
```

Para conexão padrão via `stdio` (usada pelo Claude Desktop e Cursor):
```bash
omotai start --mode stdio
```

## 3. Autenticação e Configuração de Agentes (API Keys)

Para que o Dashboard consiga rastrear **quais agentes** executaram cada ferramenta e calcular com precisão métricas (como o overhead de contexto ou economia de tokens), deve-se usar API Keys.

1. Com o Dashboard rodando, acesse `http://localhost:8080`.
2. Vá até a aba **Agents (API Keys)**.
3. Gere uma nova chave (ex: para o agente *AITG-APP-02*).
4. Configure o seu cliente MCP para repassar essa chave.

**Exemplo (`claude_desktop_config.json`):**
```json
{
  "mcpServers": {
    "omotai-runtime": {
      "command": "omotai",
      "args": ["start", "--mode", "stdio"],
      "env": {
        "OMOTAI_AGENT_KEY": "sua-api-key-gerada-aqui"
      }
    }
  }
}
```

## 4. O Cofre de Segredos Seguros

**Regra de Ouro:** O agente de IA não deve ler segredos cruciais.
Para evitar exfiltrações via "tool poisoning", injetamos tokens pelo processo Host e os bloqueamos no output.

1. Acesse a aba **Secrets Vault** no Dashboard local.
2. Insira os segredos necessários para as ferramentas (ex: Tokens de sessão, credenciais HTTP Básicas).
3. Ao acionar uma ferramenta, o runtime injeta o segredo no processo isolado (ex: navegador ou requisição), executa a ação, mas **mascara o segredo na saída** (com `***`) e impede o vazamento no histórico do agente.

## 5. Telemetria e Hardening

No Dashboard web e nos arquivos de log locais, você notará as seguintes restrições ativadas automaticamente (Hardening B):

- **Rotação Automática:** Logs são truncados se ultrapassarem o tamanho máximo em megabytes, evitando ataques por exaustão de disco (`audit.log`).
- **Sanitização Universal:** Argumentos recebidos das ferramentas (paths de arquivos e strings longas) são limpos de anomalias (null-bytes, path traversals).
- **Métricas:** Painéis exibindo o "Token Economics" - custo em tempo e densidade de informação entregue ao longo das sessões.

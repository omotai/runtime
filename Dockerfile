FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

WORKDIR /app

# Instala ferramentas básicas
RUN pip install --upgrade pip setuptools wheel

# Copia os arquivos do projeto
COPY . /app

# Instala a aplicação omotai-runtime
RUN pip install -e .

# Cria os diretórios necessários
RUN mkdir -p /app/runs && chmod -R 777 /app/runs

# Expõe a porta 8080 para a Dashboard (FastAPI)
EXPOSE 8080

# O comando padrão liga o servidor e o dashboard.
# No docker-compose, manteremos o stdin_open e tty ativos para não encerar o processo MCP.
CMD ["omotai", "start", "--dashboard", "--port", "8080", "--policy", "/app/policy.yaml"]

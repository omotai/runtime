FROM mcr.microsoft.com/playwright/python:v1.63.0-jammy

WORKDIR /app

# Instala ferramentas básicas
RUN pip install --upgrade pip setuptools wheel

# Copia os arquivos do projeto
COPY . /app

# Instala a aplicação
RUN pip install -e .

# Cria os diretórios necessários
RUN mkdir -p /app/runs && chmod -R 777 /app/runs

# Expõe a porta 8000 para o MCP (SSE)
EXPOSE 8000

# O comando padrão liga apenas o runtime
CMD ["omotai", "start", "--mode", "sse", "--port", "8000", "--policy", "/app/policy.yaml"]

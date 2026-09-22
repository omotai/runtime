FROM python:3.12-slim

WORKDIR /app

# Instala ferramentas básicas
RUN pip install --upgrade pip setuptools wheel

# Copia os arquivos do projeto
COPY . /app

# Instala a aplicação otimizada sem baixar os navegadores do playwright
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
RUN pip install -e .

# Cria os diretórios necessários
RUN mkdir -p /app/runs && chmod -R 777 /app/runs

# Expõe a porta 8080 para a Dashboard (FastAPI)
EXPOSE 8080

# O comando padrão liga apenas a dashboard
CMD ["omotai", "start", "--dashboard", "--port", "8080", "--policy", "/app/policy.yaml"]

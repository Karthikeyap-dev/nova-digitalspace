FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 NOVA_DATA_DIR=/app/data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 10001 nova \
    && mkdir -p /app/data/uploads \
    && chown -R nova:nova /app
COPY --chown=nova:nova backend ./backend
COPY --chown=nova:nova frontend ./frontend
USER nova
EXPOSE 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]

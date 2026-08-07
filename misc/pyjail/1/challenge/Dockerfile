FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLAG=VTCH{4st_w4lker_c4nt_st0p_th3_d4rk_dund3rs!!}
ENV PORT=31339

RUN useradd --system --uid 10001 --create-home ctf

WORKDIR /app
COPY server.py /app/server.py
COPY flag.txt /app/flag.txt

RUN chown -R ctf:ctf /app

USER ctf
EXPOSE 31339

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python3 -c "import os,socket; s=socket.create_connection(('127.0.0.1', int(os.environ.get('PORT','31339'))), 2); s.close()"

CMD ["sh", "-c", "exec python3 /app/server.py"]

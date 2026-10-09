FROM python:3.12-slim

WORKDIR /app

# 复制已包含的完整编译产物与服务器
COPY dist ./dist
COPY server.py ./server.py

# Zeabur 环境变量支持 (动态端口与持久化数据目录)
ENV PORT=3000     PERSIST_DIR=/data

RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 3000

CMD ["python", "server.py"]

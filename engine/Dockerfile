FROM python:3.12-slim
WORKDIR /opt/webscan
COPY webscan.py app.py ./
COPY wscan ./wscan
COPY rules ./rules
# UI binds localhost inside the container; publish with -p 127.0.0.1:8777:8777
EXPOSE 8777
CMD ["python3", "app.py", "--port", "8777"]

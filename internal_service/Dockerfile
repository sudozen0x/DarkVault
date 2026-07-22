FROM python:3.12-slim
WORKDIR /srv
RUN pip install --no-cache-dir flask
COPY app.py .
EXPOSE 9000
CMD ["python", "app.py"]

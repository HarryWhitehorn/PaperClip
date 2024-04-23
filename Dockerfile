FROM python:3.11

WORKDIR /app

# COPY
COPY server /app/server
# COPY client /app/client
COPY rps /app/rps
COPY udp /app/udp
COPY .env /app/.env
COPY requirements.txt /app/requirements.txt

# RUN
RUN pip install --no-cache-dir -r requirements.txt

# ENV
ENV FLASK_APP=server
ENV FLASK_ENV=development

# CMD
CMD ["flask", "run", "--host=0.0.0.0"]

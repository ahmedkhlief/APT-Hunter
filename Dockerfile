FROM python:3.8-slim

WORKDIR /usr/apt_hunter

COPY requirements.txt .

RUN pip install -r requirements.txt

COPY . .

ENTRYPOINT [ "python", "./APT-Hunter.py"]

CMD [ "-h" ]

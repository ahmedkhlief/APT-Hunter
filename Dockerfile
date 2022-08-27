FROM python:3.7

WORKDIR /apt-hunter
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
ENTRYPOINT [ "python", "./APT-Hunter.py" ]

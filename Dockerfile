FROM python:3.7

WORKDIR /apt-hunter
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENTRYPOINT [ "python", "./APT-Hunter.py" ]

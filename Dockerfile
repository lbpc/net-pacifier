FROM pypy:3
ENV TZ Europe/Moscow
WORKDIR /pacifier
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY src .
CMD [ "pypy3", "./main.py" ]

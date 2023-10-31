FROM python:3.8.17

ADD . /drheader

WORKDIR drheader

RUN pip install .

ENTRYPOINT drheader

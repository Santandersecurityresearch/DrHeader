FROM python:3.7.4

ADD . /drheader

WORKDIR drheader

RUN pip install .

ENTRYPOINT drheader

FROM		python:2.7
MAINTAINER	Sean Houghton <sean.houghton@activision.com>

COPY		requirements.txt /tmp/requirements.txt

RUN			pip install -r /tmp/requirements.txt && \
			rm /tmp/requirements.txt

COPY		p4exporter /usr/local/bin/p4exporter.py

EXPOSE		8666
ENTRYPOINT	["/bin/python", "/usr/local/bin/p4exporter.py"]
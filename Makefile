NAME=seanhoughton/p4-exporter
TAG=latest

.PHONY: image dev

image:
	docker build -t $(NAME):$(TAG) .

dev:
	-docker stop p4-exporter
	docker run --name p4-exporter -d --rm -p 9666:9666 -v $(CURDIR):/local -w /local --entrypoint "python" $(NAME):$(TAG) p4exporter.py --config=/local/config.yml --verbose
	docker logs -f p4-exporter

default: image
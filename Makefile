NAME=seanhoughton/p4-exporter
TAG=latest

.PHONY: image

image:
	docker build -t $(NAME):$(TAG) .


default: image
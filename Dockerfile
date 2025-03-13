FROM ubuntu:latest
LABEL authors="jones"

ENTRYPOINT ["top", "-b"]
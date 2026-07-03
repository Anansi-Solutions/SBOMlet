# Minimal image for the Docker-scan workflow: a small Alpine base plus a
# native package layer and two application-layer package slivers (an npm
# package and a Python wheel's dist-info), so a full-image scan sees both OS
# and application packages.
FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY app-pkg/ /srv/app/node_modules/is-odd/
COPY pydist/ /usr/lib/python3.12/site-packages/typing_extensions-4.12.2.dist-info/

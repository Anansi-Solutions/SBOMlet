# Minimal image for the Docker-scan workflow: a small Alpine base plus a
# native package layer and two application-layer package slivers (an npm
# package and a Python wheel's dist-info), so a full-image scan sees both OS
# and application packages. Nothing here is used by the tool; the fabricated
# demo-* packages exist only so a scan finds application-layer content.
FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY app-pkg/ /srv/app/node_modules/demo-npm-package/
COPY pydist/ /usr/lib/python3.12/site-packages/demo_python_package-0.0.0.dist-info/

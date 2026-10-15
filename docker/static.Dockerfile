FROM docker.io/library/nginx:stable-alpine@sha256:c36c74649f425d29473146f051ab9a032874a6989942557acb8ab1e215c6c2d8
COPY nginx.conf /etc/nginx/nginx.conf
COPY site/ /usr/share/nginx/html/
HEALTHCHECK --interval=15s --timeout=5s --retries=3 CMD wget -q --spider http://127.0.0.1/

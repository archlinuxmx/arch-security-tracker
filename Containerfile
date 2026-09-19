# syntax=docker/dockerfile:1
ARG ARCH_IMAGE=docker.io/library/archlinux:base

FROM ${ARCH_IMAGE}
COPY deploy/arch-packages /tmp/tracker-packages
# Keep Python, pyalpm and libalpm in the same package transaction.
RUN pacman -Syu --needed --noconfirm $(cat /tmp/tracker-packages) \
    && pacman -Scc --noconfirm \
    && python -c 'import pyalpm; print(pyalpm.alpmversion())' \
    && rm -rf /etc/pacman.d/gnupg/private-keys-v1.d /etc/pacman.d/gnupg/openpgp-revocs.d \
    && rm -f /tmp/tracker-packages \
    && groupadd --gid 10001 tracker \
    && useradd --uid 10001 --gid 10001 --no-create-home \
         --home-dir /var/lib/tracker --shell /usr/bin/nologin tracker \
    && install -d -o 10001 -g 10001 -m 0750 /var/lib/tracker

WORKDIR /opt/tracker
COPY config.py trackerctl LICENSE ./
COPY config/00-default.conf config/00-default.conf
COPY tracker/ tracker/
COPY migrations/ migrations/
COPY .external/normalize.css/normalize.css .external/normalize.css/normalize.css
COPY .external/archlinux-common-style/html/navbar.html .external/archlinux-common-style/html/navbar.html
COPY .external/archlinux-common-style/img/ .external/archlinux-common-style/img/
COPY deploy/entrypoint.py deploy/gunicorn.conf.py deploy/
RUN test -s tracker/templates/navbar.html \
    && test -s tracker/static/normalize.css \
    && test -s tracker/static/archlogo.8a05bc7f6cd1.svg \
    && test -s tracker/static/favicon.ico \
    && chmod -R a+rX /opt/tracker

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/opt/tracker \
    TRACKER_CONFIG_LOCAL=false TRACKER_DATA_DIR=/var/lib/tracker
LABEL org.opencontainers.image.title="Arch Security Tracker" \
      org.opencontainers.image.source="https://github.com/denisse-dev/arch-security-tracker" \
      org.opencontainers.image.licenses="MIT"
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).close()"]
ENTRYPOINT ["python", "/opt/tracker/deploy/entrypoint.py"]
CMD ["serve"]

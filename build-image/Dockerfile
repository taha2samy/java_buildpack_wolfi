FROM chainguard/wolfi-base:latest

USER root
RUN apk add --no-cache \
    bash \
    gzip \
    curl \
    shadow \
    python3 \
    py3-pip \
    posix-libc-utils \
    build-base \
    libffi-dev && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
    rich \
    jinja2 \
    pyinstaller \
    --break-system-packages


ENV CNB_USER_ID=1001
ENV CNB_GROUP_ID=1001

RUN groupadd -g ${CNB_GROUP_ID} cnb && \
    useradd -u ${CNB_USER_ID} -g ${CNB_GROUP_ID} -s /bin/bash -m cnb

LABEL io.buildpacks.stack.id="io.fckfips.stacks.wolfi"

RUN mkdir -p /tmp && chmod 1777 /tmp

USER ${CNB_USER_ID}:${CNB_GROUP_ID}

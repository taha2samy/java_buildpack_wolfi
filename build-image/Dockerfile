FROM chainguard/wolfi-base@sha256:9925d3017788558fa8f27e8bb160b791e56202b60c91fbcc5c867de3175986c8 

USER root

RUN apk update && \
    apk add --no-cache \
    bash \
    gzip \
    curl \
    shadow \
    python3 \
    py3-pip

RUN pip install --no-cache-dir \
    rich \
    jinja2 \
    --break-system-packages

ENV CNB_USER_ID=1001
ENV CNB_GROUP_ID=1001

RUN groupadd -g ${CNB_GROUP_ID} cnb && \
    useradd -u ${CNB_USER_ID} -g ${CNB_GROUP_ID} -s /bin/bash -m cnb

LABEL io.buildpacks.stack.id="taha/wolfi-build-image"

RUN mkdir -p /tmp && chmod 1777 /tmp

USER ${CNB_USER_ID}:${CNB_GROUP_ID}
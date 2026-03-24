# syntax=docker/dockerfile:1.6

FROM chainguard/wolfi-base@sha256:9925d3017788558fa8f27e8bb160b791e56202b60c91fbcc5c867de3175986c8 AS helper

RUN (addgroup -g 1001 java || true) && (adduser -u 1001 -G java -D -s /sbin/nologin java || true)
RUN mkdir -p /rootfs/etc /rootfs/usr/share/zoneinfo /rootfs/home/java /rootfs/tmp

RUN cp /etc/passwd /rootfs/etc/passwd && \
    cp /etc/group /rootfs/etc/group && \
    echo "hosts: files dns" > /rootfs/etc/nsswitch.conf && \
    echo "UTC" > /rootfs/etc/timezone && \
    chown 1001:1001 /rootfs/home/java && \
    chmod 1777 /rootfs/tmp


FROM chainguard/wolfi-base@sha256:9925d3017788558fa8f27e8bb160b791e56202b60c91fbcc5c867de3175986c8 AS producer
USER root

RUN mkdir -p /rootfs/run_distroless/etc/apk /rootfs/run_distroless/var/lib/apk

RUN --mount=type=cache,id=wolfi-apk,target=/var/cache/apk \
    apk add --initdb --no-scripts --root /rootfs/run_distroless \
    --cache-dir /var/cache/apk --keys-dir /etc/apk/keys --repositories-file /etc/apk/repositories \
    glibc=2.43-r1 zlib=1.3.2-r0 ca-certificates=20251003-r3 wolfi-baselayout=20230201-r28 \
    wolfi-keys=1-r13 libgcc=15.2.0-r9 libstdc++=15.2.0-r9 tzdata=2026a-r0 && \
    ldconfig -r /rootfs/run_distroless


FROM scratch

COPY --from=producer /rootfs/run_distroless /
COPY --from=helper /rootfs /

ENV CNB_USER_ID=1001
ENV CNB_GROUP_ID=1001
ENV LANG=C.UTF-8 TZ=UTC

LABEL io.buildpacks.stack.id="taha/wolfi-build-image"

USER 1001
WORKDIR /home/java


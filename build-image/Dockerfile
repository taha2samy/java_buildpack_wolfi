FROM ghcr.io/taha2samy/java:8-jdk_standard AS jdk8
FROM ghcr.io/taha2samy/java:11-jdk_standard AS jdk11
FROM ghcr.io/taha2samy/java:17-jdk_standard AS jdk17
FROM ghcr.io/taha2samy/java:21-jdk_standard AS jdk21
FROM ghcr.io/taha2samy/java:25-jdk_standard AS jdk25

FROM ghcr.io/taha2samy/java:8-jre_distroless AS jre8
FROM ghcr.io/taha2samy/java:11-jre_distroless AS jre11
FROM ghcr.io/taha2samy/java:17-jre_distroless AS jre17
FROM ghcr.io/taha2samy/java:21-jre_distroless AS jre21
FROM ghcr.io/taha2samy/java:25-jre_distroless AS jre25

FROM chainguard/wolfi-base@sha256:9925d3017788558fa8f27e8bb160b791e56202b60c91fbcc5c867de3175986c8 

USER root

RUN apk update && \
    apk add --no-cache bash gzip curl jq ca-certificates shadow python3 py3-pip


RUN pip install --no-cache-dir rich --break-system-packages

RUN mkdir -p /opt/jdks /opt/jres

RUN mkdir -p /opt/jdks /opt/jres

COPY --from=jdk8 /opt/java /opt/jdks/8
COPY --from=jdk11 /opt/java /opt/jdks/11
COPY --from=jdk17 /opt/java /opt/jdks/17
COPY --from=jdk21 /opt/java /opt/jdks/21
COPY --from=jdk25 /opt/java /opt/jdks/25

COPY --from=jre8 /opt/java /opt/jres/8
COPY --from=jre11 /opt/java /opt/jres/11
COPY --from=jre17 /opt/java /opt/jres/17
COPY --from=jre21 /opt/java /opt/jres/21
COPY --from=jre25 /opt/java /opt/jres/25

ENV CNB_USER_ID=1001
ENV CNB_GROUP_ID=1001

RUN groupadd -g ${CNB_GROUP_ID} cnb && \
    useradd -u ${CNB_USER_ID} -g ${CNB_GROUP_ID} -s /bin/bash -m cnb

LABEL io.buildpacks.stack.id="taha/wolfi-build-image"

RUN chown -R ${CNB_USER_ID}:${CNB_GROUP_ID} /opt/jdks /opt/jres && \
    chmod -R 755 /opt/jdks /opt/jres

USER ${CNB_USER_ID}:${CNB_GROUP_ID}
FROM golang:1.17-alpine as helper
WORKDIR /go/src/
COPY . .
RUN CGO_ENABLED=0 GOFLAGS=-mod=vendor go build -ldflags="-s -w" -trimpath .

FROM gcr.io/distroless/static:latest-amd64

ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="bdwyertech/gitlab-security-report-gate" \
    org.opencontainers.image.description="Fail a GitLab pipeline if a security report has vulnerabilities" \
    org.opencontainers.image.authors="Brian Dwyer <bdwyertech@github.com>" \
    org.opencontainers.image.url="https://hub.docker.com/r/bdwyertech/gitlab-security-report-gate" \
    org.opencontainers.image.source="https://github.com/bdwyertech/gitlab-security-report-gate.git" \
    org.opencontainers.image.revision=$VCS_REF \
    org.opencontainers.image.created=$BUILD_DATE \
    org.label-schema.name="bdwyertech/gitlab-security-report-gate" \
    org.label-schema.description="Fail a GitLab pipeline if a security report has vulnerabilities" \
    org.label-schema.url="https://hub.docker.com/r/bdwyertech/gitlab-security-report-gate" \
    org.label-schema.vcs-url="https://github.com/bdwyertech/gitlab-security-report-gate.git" \
    org.label-schema.vcs-ref=$VCS_REF \
    org.label-schema.build-date=$BUILD_DATE

COPY --from=helper /go/src/gitlab-security-report-gate /.
CMD ["/gitlab-security-report-gate"]

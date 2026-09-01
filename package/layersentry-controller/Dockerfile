FROM scratch

ARG CONTROLLER_VERSION
ARG SOURCE_COMMIT
ARG BUILD_EPOCH

LABEL org.opencontainers.image.title="LayerSentry bootstrap controller" \
      org.opencontainers.image.description="Read-only LayerSentry v1.0 bootstrap-validation API for embedded Harvester v1.8.2" \
      org.opencontainers.image.source="https://github.com/adaptgurus/harvester-installer" \
      org.opencontainers.image.version="${CONTROLLER_VERSION}" \
      org.opencontainers.image.revision="${SOURCE_COMMIT}" \
      org.opencontainers.image.created="${BUILD_EPOCH}" \
      io.layersentry.product="LayerSentry" \
      io.layersentry.product-version="v1.0" \
      io.layersentry.embedded-platform="Harvester" \
      io.layersentry.embedded-platform-version="v1.8.2" \
      io.layersentry.lifecycle="BUNDLED_NOT_INSTALLED" \
      io.layersentry.runtime-qualified="false" \
      io.layersentry.release-approved="false"

COPY --chmod=0555 bin/layersentry-controller /usr/local/bin/layersentry-controller

USER 65532:65532
EXPOSE 9443
ENTRYPOINT ["/usr/local/bin/layersentry-controller"]
CMD ["--listen", "0.0.0.0:9443"]

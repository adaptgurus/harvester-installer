FROM registry.suse.com/bci/bci-base@sha256:ad95af6d4b236fa9854b30fc156984456c83dc7dd51684e200844e721861f542

RUN zypper -n rm container-suseconnect && \
    zypper -n in nginx && \
    zypper -n clean -a && rm -rf /tmp/* /var/tmp/* /usr/share/doc/packages/* && \
    ln -sf /dev/stdout /var/log/nginx/access.log && \
    ln -sf /dev/stderr /var/log/nginx/error.log

COPY charts /srv/www/htdocs/charts

RUN touch /run/nginx.pid && \
    chown nginx:nginx /run/nginx.pid && \
    chown -R nginx:nginx /srv/www/htdocs/charts

USER nginx

EXPOSE 80

STOPSIGNAL SIGQUIT

# This source-only marker intentionally retriggers the reviewed final
# generated-image and full-offline ISO provenance workflow.
LABEL io.layersentry.provenance-rerun="2026-09-03-installer-ux-v182-rebased"

CMD ["nginx", "-g", "daemon off;"]

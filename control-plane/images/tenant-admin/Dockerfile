FROM python:3.12-alpine

# bind-tools -- dig, for the DNS page's "Check records" live-lookup button.
RUN apk add --no-cache bind-tools

COPY requirements-lock.txt /requirements-lock.txt
RUN pip install --no-cache-dir -r /requirements-lock.txt

COPY app.py /app.py
# Pre-built CodeMirror bundle for the Files page's editor (see
# static/README.md for how it's built) -- only the two files Flask's
# default static_folder actually needs to serve at runtime; src/ (the
# unminified entry point + package.json used to rebuild it) stays out
# of the image on purpose, no reason to publish a package.json over
# this container's own static route.
COPY static/vhsp-editor.bundle.js static/vhsp-editor.bundle.js.LICENSE.txt /static/

EXPOSE 80

# gunicorn, not `python /app.py` (Flask's own dev server) -- same reason
# as vhsp_ctl/web.py's identical swap (see deploy/vhsp-admin.service).
# Sessions are cookie-based, not server-side, so the extra worker process
# needs no shared state. Working directory is `/` (this image's default,
# never overridden), where app.py was COPY'd -- gunicorn's own import
# mechanism adds the cwd to sys.path the same way `python /app.py` did.
CMD ["gunicorn", "--workers", "2", "--bind", "0.0.0.0:80", "app:app"]

# Updating a vhsp deployment

This is the procedure the admin UI's update banner links to. It assumes a
host installed per [`control-plane/DEPLOYMENT.md`](control-plane/DEPLOYMENT.md).

**There is no automatic update, deliberately.** The control plane is
root-equivalent on its host — it reaches Docker through a scoped proxy
and holds sudo grants to a set of root-owned wrapper scripts. A
root-equivalent process that fetches and applies code from the internet
on its own is exactly the supply-chain failure this project exists as a
reaction to. The banner tells you a release exists; applying it is a
decision you make, with these steps.

---

## Before you start

```
vhsp update status      # what you're running vs. the latest release
vhsp audit verify       # confirm the audit chain is intact beforehand
```

Read the release notes for the version you're moving to. Anything needing
a manual step — a new environment variable, a wrapper script to
reinstall, a container image to rebuild — is called out there.

**Take a rollback snapshot.** Tenant data lives on volumes and isn't
touched by a code update, but the checkout is worth being able to put
back:

```
sudo tar czf /root/vhsp-pre-update-$(date +%Y%m%d-%H%M%S).tar.gz \
  --exclude=.venv --exclude=__pycache__ \
  -C /home/<control-plane-user> vhsp-control-plane
```

---

## 1. Get the new code onto the host

From your local checkout, on the tag you're deploying:

```
git fetch --tags
git checkout v<version>

rsync -az --delete \
  --exclude '.venv' --exclude '__pycache__' --exclude '*.egg-info' \
  --exclude 'deploy/rendered' --exclude '.pytest_cache' \
  ./control-plane/ <user>@<host>:/home/<user>/vhsp-control-plane/
```

`--delete` is intentional — it removes files a previous version left
behind. The excludes matter: `.venv` and `deploy/rendered/` are built on
the host and must survive.

## 2. Update dependencies

Only needed when the release notes say dependencies changed, but it's
harmless to run every time:

```
cd ~/vhsp-control-plane
.venv/bin/pip install -r requirements-lock.txt
.venv/bin/pip install -e .
```

## 3. Re-render the deployment templates

The systemd units and sudoers grant are committed with `__VHSP_USER__` /
`__VHSP_HOME__` placeholders and rendered per host, so a release that
changes any of them needs this step:

```
./deploy/vhsp-render --user <control-plane-user>
```

Then reinstall **only** what the release notes say changed, from
`deploy/rendered/` — never from the templates beside it.

> **Do not blanket-copy the units over your installed ones.** The
> installed copies under `/etc/systemd/system` carry deployment-specific
> values the repo ships blank: the backup SFTP destination, the WebAuthn
> RP ID, the public IP, the mail gateway hostname. Overwriting them
> silently sends backups nowhere, and resetting the RP ID stops every
> registered security key from verifying, because WebAuthn binds
> credentials to that exact origin. Diff first and carry your values
> across by hand:
>
> ```
> diff /etc/systemd/system/vhsp-admin.service deploy/rendered/vhsp-admin.service
> ```

Wrapper scripts in `/usr/local/sbin/` have no such per-host values and
can be reinstalled directly when a release changes them:

```
sudo install -o root -g root -m 0755 deploy/rendered/vhsp-<script> /usr/local/sbin/
```

If the sudoers grant changed, stage and validate it before it goes live —
a malformed file in `/etc/sudoers.d/` can lock sudo out of the host
entirely:

```
sudo cp deploy/rendered/vhsp-sudoers /etc/sudoers.d/<user>.new
sudo visudo -cf /etc/sudoers.d/<user>.new
sudo mv /etc/sudoers.d/<user>.new /etc/sudoers.d/<user>
```

## 4. Rebuild container images, if the release changed them

Changes under `images/` only reach tenants when the images are rebuilt
and the containers recreated:

```
docker build -t vhsp-web:latest images/web
docker build -t vhsp-mail:latest images/mail
docker build -t vhsp-mailgw:latest images/mailgw
docker build -t vhsp-tenant-admin:latest images/tenant-admin
```

Recreating tenant containers is per-image and tenant-affecting — use the
`recreate_*.py` helpers, and expect brief downtime for the tenants
involved.

## 5. Restart the control plane

```
sudo systemctl daemon-reload            # only if a unit file changed
sudo systemctl restart vhsp-admin.service
```

The backup, reconcile, audit-ship, and update-check units are `oneshot`
jobs started by timers — they pick up new code on their next run with no
restart needed.

---

## Verify

```
vhsp update status                      # should now report the new version
systemctl is-active vhsp-admin.service
vhsp audit verify
vhsp tenant list
journalctl -u vhsp-admin.service --since '5 min ago' | tail -20
```

Then load the admin UI and log in — that exercises the session, 2FA, and
template paths in one go. The update banner should be gone.

## Rolling back

Restore the snapshot from before you started and restart:

```
sudo tar xzf /root/vhsp-pre-update-<timestamp>.tar.gz -C /home/<user>
sudo systemctl restart vhsp-admin.service
```

Tenant data is unaffected by a code rollback. If the release ran a
one-way data migration, the release notes will say so — check before
rolling back rather than after.

---

## About the update check

It's **opt-in and off by default**. It is the only outbound HTTP request
anything in this codebase makes, which on a self-hosted platform is the
operator's call rather than a default:

```
vhsp update enable       # allow the daily check + admin-UI banner
vhsp update disable
vhsp update check        # check once, right now, regardless of the toggle
```

It requests one URL — the GitHub Releases API for this repo — and stores
only the tag, release URL, and publish date. It never fetches release
notes into the UI, and it never downloads code.

To install the timer:

```
sudo cp deploy/rendered/vhsp-update-check.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vhsp-update-check.timer
```

## Cutting a release (maintainers)

1. Bump `__version__` in `control-plane/vhsp_ctl/__init__.py` — the single
   source of truth; `pyproject.toml` reads it from there.
2. Commit, then tag that commit `v<version>` and push the tag.
3. `.github/workflows/release.yml` turns the tag into a GitHub Release
   with generated notes. Edit it to call out any manual steps operators
   need, since that text is what they'll act on.

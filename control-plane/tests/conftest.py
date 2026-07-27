"""Point STATE_DIR at a throwaway directory before anything imports config.

`vhsp_ctl.web` calls `auth.ensure_secret_key()` at import time, which
creates STATE_DIR -- `/srv/vhsp` by default, not writable by a test
runner (or a CI runner) and not something a test should be touching
even where it is. config.py reads this env var at import, so it has to
be set before the first `vhsp_ctl.*` import; pytest loads conftest.py
ahead of collecting test modules, which is what makes this the right
place for it.
"""

import os
import tempfile

os.environ.setdefault("VHSP_STATE_DIR", tempfile.mkdtemp(prefix="vhsp-test-state-"))

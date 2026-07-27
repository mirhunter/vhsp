# vhsp-editor.bundle.js

`vhsp-editor.bundle.js` is a pre-built, minified bundle of CodeMirror 6
(the editor behind the Files page's "Edit" view, replacing a plain
`<textarea>`) -- committed to the repo so the tenant-admin container
image needs nothing beyond Python at build time. Vendored, not loaded
from a CDN, matching this project's "no external runtime dependencies"
posture elsewhere (see control-plane/README.md).

Source lives in `src/vhsp-editor.entry.js`; `src/package.json` pins the
exact CodeMirror package versions the committed bundle was built from.
`app.py`'s `files_edit()` route and `FILES_EDIT_PAGE` template are
unaffected by anything in here -- `vhspMountEditor()` (defined in the
entry file) only swaps the client-side input widget; it syncs back into
the original `<textarea>` on every keystroke, so the server still just
sees a normal `request.form["content"]` POST.

## Rebuilding after an entry.js change or a CodeMirror version bump

Needs Node/npm (not required at container-build time, only here):

```
cd src
npm install
npm run build
```

Regenerates `../vhsp-editor.bundle.js` in place. Commit both the
updated bundle and any `src/package-lock.json` change together.

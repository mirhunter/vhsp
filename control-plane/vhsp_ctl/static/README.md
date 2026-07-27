# Vendored static assets

`swagger-ui-bundle.js`, `swagger-ui-standalone-preset.js`, and
`swagger-ui.css` are the pre-built `swagger-ui-dist` npm package
(version 5.32.11 when last vendored), used by `vhsp_ctl/api.py`'s
`/api/v1/docs` page to render the operator API's OpenAPI spec
interactively. Vendored, not CDN-loaded -- same posture as
`images/tenant-admin/static/`'s CodeMirror bundle.

## Updating

```
cd /tmp && npm init -y >/dev/null && npm install swagger-ui-dist
cp node_modules/swagger-ui-dist/swagger-ui-bundle.js \
   node_modules/swagger-ui-dist/swagger-ui-standalone-preset.js \
   node_modules/swagger-ui-dist/swagger-ui.css \
   <this directory>
```

No build step -- it's a pre-built distribution, not source that needs
compiling (unlike the CodeMirror bundle, which has its own `src/` and
`npm run build`). Update the version number in
`swagger-ui.LICENSE.txt`'s own header comment when you do.

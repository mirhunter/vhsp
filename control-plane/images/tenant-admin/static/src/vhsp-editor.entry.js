import { EditorView, basicSetup } from "codemirror";
import { EditorState } from "@codemirror/state";
import { indentWithTab } from "@codemirror/commands";
import { keymap } from "@codemirror/view";
import { javascript } from "@codemirror/lang-javascript";
import { css } from "@codemirror/lang-css";
import { html } from "@codemirror/lang-html";
import { json } from "@codemirror/lang-json";
import { php } from "@codemirror/lang-php";
import { sql } from "@codemirror/lang-sql";
import { python } from "@codemirror/lang-python";
import { markdown } from "@codemirror/lang-markdown";
import { yaml } from "@codemirror/lang-yaml";
import { xml } from "@codemirror/lang-xml";
import { oneDark } from "@codemirror/theme-one-dark";

// Extension -> language-support factory. Anything not listed here still
// gets the plain editor shell (line numbers, bracket matching, etc via
// basicSetup) with no syntax highlighting, rather than being refused --
// same "don't be exhaustive, fall back gracefully" posture as the
// server-side FILES_TEXT_EXTENSIONS/_is_text_file split in app.py.
const LANG_BY_EXT = {
  php: php, phtml: php,
  js: javascript, mjs: javascript, jsx: () => javascript({ jsx: true }),
  ts: () => javascript({ typescript: true }),
  tsx: () => javascript({ jsx: true, typescript: true }),
  css: css,
  html: html, htm: html,
  json: json,
  sql: sql,
  py: python,
  md: markdown, markdown: markdown,
  yml: yaml, yaml: yaml,
  xml: xml, svg: xml,
};

function langExtensionFor(filename) {
  const dot = filename.lastIndexOf(".");
  const ext = dot === -1 ? "" : filename.slice(dot + 1).toLowerCase();
  const factory = LANG_BY_EXT[ext];
  return factory ? [factory()] : [];
}

// Mounts a CodeMirror 6 editor next to `textarea`, hides the original
// element (kept in the DOM, not removed -- its `name` attribute is what
// the surrounding <form> actually submits), and keeps it in sync on
// every keystroke so the existing server-side POST handler
// (files_edit() in app.py, `request.form.get("content", "")`) needs no
// changes at all -- this is purely a client-side swap of the input
// widget, not a new save path.
//
// Theme follows prefers-color-scheme, not a hardcoded dark theme --
// same "OS setting, not a stateful toggle" posture as this app's own
// DARK_AWARE_CSS (see app.py). oneDark only applied under the dark
// media query; CodeMirror's own default (no theme extension) is
// already a clean light theme, so nothing extra is needed for light
// mode.
window.vhspMountEditor = function (textarea, filename) {
  textarea.style.display = "none";
  const host = document.createElement("div");
  host.className = "vhsp-cm-editor";
  textarea.insertAdjacentElement("afterend", host);

  const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;

  const view = new EditorView({
    state: EditorState.create({
      doc: textarea.value,
      extensions: [
        basicSetup,
        keymap.of([indentWithTab]),
        ...(prefersDark ? [oneDark] : []),
        ...langExtensionFor(filename),
        EditorView.updateListener.of((update) => {
          if (update.docChanged) textarea.value = update.state.doc.toString();
        }),
      ],
    }),
    parent: host,
  });

  const form = textarea.closest("form");
  if (form) {
    // Belt and suspenders on top of the updateListener above -- covers
    // the (normally unreachable) case of a submit firing before the
    // listener's own microtask settles.
    form.addEventListener("submit", () => {
      textarea.value = view.state.doc.toString();
    });
  }
  return view;
};

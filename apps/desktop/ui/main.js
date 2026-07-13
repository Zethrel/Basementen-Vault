// Basementen Vault desktop UI. Plain JS over the Tauri command bridge —
// no framework, no build step, no external dependencies (CSP forbids them).
"use strict";

const invoke = window.__TAURI__.core.invoke;

const $ = (id) => document.getElementById(id);
const screens = ["screen-setup", "screen-recovery", "screen-unlock", "screen-vault"];

let mode = "login";           // setup screen tab
let selectedId = null;        // item currently in the editor
let statusTimer = null;

function show(screenId) {
  for (const s of screens) $(s).hidden = s !== screenId;
}

async function refreshStatus() {
  const st = await invoke("status");
  if (st.state === "unlocked") {
    if ($("screen-vault").hidden) {
      show("screen-vault");
      await renderList();
    }
  } else if (st.state === "locked") {
    if ($("screen-unlock").hidden && $("screen-setup").hidden && $("screen-recovery").hidden) {
      show("screen-unlock");
    } else if (!$("screen-vault").hidden) {
      // Auto-lock fired while the vault was open.
      selectedId = null;
      show("screen-unlock");
    }
    $("unlock-email").textContent = st.email ?? "";
  } else if ($("screen-recovery").hidden) {
    show("screen-setup");
  }
}

// ---------------------------------------------------------------------------
// Setup (login / register)

function setMode(m) {
  mode = m;
  $("tab-login").classList.toggle("active", m === "login");
  $("tab-register").classList.toggle("active", m === "register");
  $("row-password2").hidden = m !== "register";
  $("row-totp").hidden = m !== "login";
  $("setup-submit").textContent = m === "login" ? "Log in" : "Create account";
  $("setup-error").textContent = "";
}
$("tab-login").addEventListener("click", () => setMode("login"));
$("tab-register").addEventListener("click", () => setMode("register"));

$("setup-submit").addEventListener("click", async () => {
  const server = $("setup-server").value.trim();
  const email = $("setup-email").value.trim();
  const password = $("setup-password").value;
  $("setup-error").textContent = "";
  $("setup-submit").disabled = true;
  try {
    if (!server || !email || !password) throw "fill in server, e-mail and password";
    if (mode === "register") {
      if (password !== $("setup-password2").value) throw "passwords do not match";
      const res = await invoke("register", { serverUrl: server, email, password });
      $("recovery-code").textContent = res.recovery_code;
      $("recovery-ack").checked = false;
      $("recovery-done").disabled = true;
      show("screen-recovery");
    } else {
      const totp = $("setup-totp").value.trim();
      await invoke("login", {
        serverUrl: server, email, password,
        totpCode: totp.length ? totp : null,
      });
      $("setup-password").value = "";
      show("screen-vault");
      await renderList();
    }
  } catch (e) {
    $("setup-error").textContent = String(e);
  } finally {
    $("setup-submit").disabled = false;
  }
});

$("recovery-copy").addEventListener("click", async () => {
  await invoke("copy_secret", { text: $("recovery-code").textContent });
  $("recovery-copy").textContent = "Copied (clears in 30 s)";
});
$("recovery-ack").addEventListener("change", (e) => {
  $("recovery-done").disabled = !e.target.checked;
});
$("recovery-done").addEventListener("click", () => {
  setMode("login");
  show("screen-setup");
});

// ---------------------------------------------------------------------------
// Unlock

$("unlock-submit").addEventListener("click", doUnlock);
$("unlock-password").addEventListener("keydown", (e) => {
  if (e.key === "Enter") doUnlock();
});
async function doUnlock() {
  $("unlock-error").textContent = "";
  $("unlock-submit").disabled = true;
  try {
    await invoke("unlock", { password: $("unlock-password").value });
    $("unlock-password").value = "";
    show("screen-vault");
    await renderList();
  } catch (e) {
    $("unlock-error").textContent = String(e);
  } finally {
    $("unlock-submit").disabled = false;
  }
}
$("unlock-switch").addEventListener("click", () => {
  setMode("login");
  show("screen-setup");
});

// ---------------------------------------------------------------------------
// Vault list & editor

$("btn-lock").addEventListener("click", async () => {
  await invoke("lock");
  selectedId = null;
  show("screen-unlock");
});

$("btn-sync").addEventListener("click", async () => {
  const s = await invoke("sync_now");
  $("sync-status").textContent = s.offline
    ? "offline — changes queued"
    : `synced ↑${s.pushed} ↓${s.pulled}` + (s.conflicts ? ` ⚠${s.conflicts}` : "");
  await renderList();
});

$("search").addEventListener("input", () => renderList());

async function renderList() {
  const items = await invoke("list_items", { query: $("search").value });
  const ul = $("item-list");
  ul.textContent = "";
  for (const it of items) {
    const li = document.createElement("li");
    li.dataset.id = it.item_id;
    li.classList.toggle("selected", it.item_id === selectedId);
    const kind = document.createElement("span");
    kind.className = "kind";
    kind.textContent = it.kind;
    const name = document.createElement("span");
    name.className = "name";
    name.textContent = it.name;
    const sub = document.createElement("span");
    sub.className = "sub";
    sub.textContent = it.subtitle;
    li.append(kind, name, sub);
    li.addEventListener("click", () => openItem(it.item_id));
    ul.append(li);
  }
}

function setEditorKind(kind) {
  $("f-type").value = kind;
  document.querySelectorAll(".kind-fields").forEach((el) => {
    el.hidden = !el.dataset.kinds.includes(kind);
  });
}
$("f-type").addEventListener("change", () => setEditorKind($("f-type").value));

function clearEditor() {
  for (const id of ["f-name", "f-username", "f-password", "f-url", "f-notes",
    "f-tags", "f-cardholder", "f-number", "f-expiry", "f-code"]) {
    $(id).value = "";
  }
  $("editor-error").textContent = "";
}

function showDetailPane(show) {
  document.querySelector(".split").classList.toggle("show-detail", show);
  $("btn-back").hidden = !show;
}
$("btn-back").addEventListener("click", () => showDetailPane(false));

$("btn-new").addEventListener("click", () => {
  selectedId = null;
  clearEditor();
  setEditorKind("login");
  $("btn-delete").hidden = true;
  $("detail-empty").hidden = true;
  $("editor").hidden = false;
  showDetailPane(true);
  $("f-name").focus();
  renderList();
});

async function openItem(id) {
  const item = await invoke("get_item", { itemId: id });
  selectedId = id;
  clearEditor();
  setEditorKind(item.type);
  $("f-name").value = item.name ?? "";
  $("f-notes").value = item.notes ?? "";
  $("f-tags").value = (item.tags ?? []).join(", ");
  if (item.type === "login") {
    $("f-username").value = item.username ?? "";
    $("f-password").value = item.password ?? "";
    $("f-url").value = item.url ?? "";
  } else if (item.type === "card") {
    $("f-cardholder").value = item.cardholder ?? "";
    $("f-number").value = item.number ?? "";
    $("f-expiry").value = item.expiry ?? "";
    $("f-code").value = item.code ?? "";
  }
  $("btn-delete").hidden = false;
  $("detail-empty").hidden = true;
  $("editor").hidden = false;
  showDetailPane(true);
  renderList();
}

function editorItem() {
  const kind = $("f-type").value;
  const tags = $("f-tags").value.split(",").map((t) => t.trim()).filter(Boolean);
  const base = { type: kind, name: $("f-name").value.trim(), notes: $("f-notes").value, tags };
  if (kind === "login") {
    return { ...base, username: $("f-username").value, password: $("f-password").value, url: $("f-url").value };
  }
  if (kind === "card") {
    return { ...base, cardholder: $("f-cardholder").value, number: $("f-number").value,
      expiry: $("f-expiry").value, code: $("f-code").value };
  }
  return base;
}

$("editor").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("editor-error").textContent = "";
  try {
    const item = editorItem();
    if (!item.name) throw "name is required";
    const res = await invoke("save_item", { itemId: selectedId, item });
    selectedId = res.item_id;
    await renderList();
  } catch (err2) {
    $("editor-error").textContent = String(err2);
  }
});

$("btn-delete").addEventListener("click", async () => {
  if (!selectedId) return;
  if (!confirm("Delete this item? It will be removed from all your devices.")) return;
  await invoke("delete_item", { itemId: selectedId });
  selectedId = null;
  clearEditor();
  $("editor").hidden = true;
  $("detail-empty").hidden = false;
  showDetailPane(false);
  await renderList();
});

$("btn-reveal").addEventListener("click", () => {
  const f = $("f-password");
  f.type = f.type === "password" ? "text" : "password";
});

document.querySelectorAll("button.copy").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const value = $(btn.dataset.copy).value;
    if (!value) return;
    await invoke("copy_secret", { text: value });
    const old = btn.textContent;
    btn.textContent = "✓";
    setTimeout(() => (btn.textContent = old), 1200);
  });
});

// ---------------------------------------------------------------------------
// Generator dialog

const genDialog = $("gen-dialog");
$("btn-generate").addEventListener("click", () => {
  genDialog.showModal();
  regenerate();
});
$("gen-length").addEventListener("input", () => {
  $("gen-length-label").textContent = $("gen-length").value;
  regenerate();
});
for (const id of ["gen-lower", "gen-upper", "gen-digits", "gen-symbols", "gen-ambiguous"]) {
  $(id).addEventListener("change", regenerate);
}
$("gen-again").addEventListener("click", regenerate);
$("gen-close").addEventListener("click", () => genDialog.close());
$("gen-use").addEventListener("click", () => {
  $("f-password").value = $("gen-output").textContent;
  genDialog.close();
});

async function regenerate() {
  try {
    const res = await invoke("generate", {
      options: {
        length: Number($("gen-length").value),
        lowercase: $("gen-lower").checked,
        uppercase: $("gen-upper").checked,
        digits: $("gen-digits").checked,
        symbols: $("gen-symbols").checked,
        exclude_ambiguous: $("gen-ambiguous").checked,
      },
    });
    $("gen-output").textContent = res.password;
    const bits = Math.round(res.entropy_bits);
    $("gen-entropy").textContent = bits;
    const fill = $("gen-meter-fill");
    fill.style.width = Math.min(100, (bits / 128) * 100) + "%";
    fill.style.background = bits < 60 ? "var(--danger)" : bits < 90 ? "orange" : "var(--ok)";
  } catch (e) {
    $("gen-output").textContent = String(e);
  }
}

// ---------------------------------------------------------------------------

setMode("login");
refreshStatus();
statusTimer = setInterval(refreshStatus, 3000);
void statusTimer;

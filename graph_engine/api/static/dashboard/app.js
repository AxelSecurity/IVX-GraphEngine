"use strict";

/**
 * IVX GraphEngine — Dashboard
 *
 * Nessun framework, nessuna build: HTML/CSS/JS puri che consumano l'API
 * REST già esposta da graph_engine.api (stesso container Docker del tool).
 * Routing via hash: "#/" = elenco sottomissioni, "#/analyses/<id>" = dettaglio.
 */

const root = document.getElementById("view-root");

// Utente autenticato (da /auth/me); null = vista login.  Le route
// /auth/* sono escluse dall'interceptor 401 (il login con credenziali
// errate DEVE mostrare il suo errore, non la vista di accesso).
let currentUser = null;

const LAYER_ORDER = ["L0", "L1", "L2", "L3", "L4", "L5", "API"];

const TRANSITION_LABELS = {
  http_3xx: "3xx",
  meta_refresh: "meta-refresh",
  js_location: "js",
  history_push: "history",
  click: "click",
  form_submit: "form",
  new_tab: "new-tab",
  gate_solved: "gate",
  ws_message: "ws",
  cloaking_probe: "cloaking",
};

// ---------------------------------------------------------------- helpers

async function fetchJSON(url, options = {}) {
  const res = await fetch(url, options);
  if (res.status === 401 && !url.startsWith("/auth/")) {
    // Sessione scaduta o assente: torna alla vista di login
    showLogin();
    const err = new Error("Sessione scaduta — accedi di nuovo.");
    err.status = 401;
    throw err;
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch (_) {
      /* risposta non JSON — usa statusText */
    }
    const err = new Error(detail);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function truncateMiddle(str, max) {
  if (!str || str.length <= max) return str || "";
  const half = Math.floor((max - 1) / 2);
  return str.slice(0, half) + "…" + str.slice(str.length - half);
}

function formatDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString("it-IT", {
    day: "2-digit",
    month: "2-digit",
    year: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function debounce(fn, ms) {
  let t = null;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

function statusBadge(status) {
  const s = status || "queued";
  const label = { queued: "In coda", running: "In corso", done: "Completata", error: "Errore" }[s] || s;
  return `<span class="badge status-${s}">${label}</span>`;
}

function classBadge(classification) {
  if (!classification) return `<span class="badge cls-none">n/d</span>`;
  const label = { benign: "Benigno", suspicious: "Sospetto", phishing: "Phishing" }[classification] || classification;
  return `<span class="badge cls-${classification}">${label}</span>`;
}

function weightChipClass(w) {
  const val = Number(w) || 0;
  if (val <= 0) return "w-0";
  if (val < 0.2) return "w-low";
  if (val < 0.4) return "w-mid";
  return "w-high";
}

function artifactUrl(targetId, stateId, filename) {
  return `/analyses/${targetId}/artifacts/${stateId}/${filename}`;
}

// ------------------------------------------------------------------ router

function currentRoute() {
  const hash = window.location.hash.replace(/^#/, "") || "/";
  const detailMatch = hash.match(/^\/analyses\/([^/]+)/);
  if (detailMatch) return { name: "detail", id: detailMatch[1] };
  if (hash === "/lists") return { name: "lists" };
  if (hash === "/users") return { name: "users" };
  return { name: "list" };
}

function navigate(hash) {
  window.location.hash = hash;
}

window.addEventListener("hashchange", render);
document.getElementById("refresh-btn").addEventListener("click", () => {
  const btn = document.getElementById("refresh-btn");
  btn.classList.add("spin");
  setTimeout(() => btn.classList.remove("spin"), 700);
  render();
});

// -------------------------------------------------------------- lightbox

const lightbox = document.getElementById("lightbox");
const lightboxImg = document.getElementById("lightbox-img");

function openLightbox(src) {
  lightboxImg.src = src;
  lightbox.classList.remove("hidden");
}
function closeLightbox() {
  lightbox.classList.add("hidden");
  lightboxImg.src = "";
}
document.getElementById("lightbox-close").addEventListener("click", closeLightbox);
lightbox.addEventListener("click", (e) => {
  if (e.target === lightbox) closeLightbox();
});
window.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    closeLightbox();
    closeDeleteDialog();
  }
});

// -------------------------------------------------------------- health poll

async function pollHealth() {
  const dot = document.getElementById("health-dot");
  const text = document.getElementById("health-text");
  try {
    const h = await fetchJSON("/health");
    dot.className = "dot " + (h.running_jobs > 0 ? "busy" : "ok");
    text.textContent = h.running_jobs > 0
      ? `${h.running_jobs} analisi in corso`
      : "operativo";
  } catch (e) {
    dot.className = "dot bad";
    text.textContent = "non raggiungibile";
  }
}
pollHealth();
setInterval(pollHealth, 12000);

// ------------------------------------------------------------------- auth
// Login/logout della dashboard: la sessione vive in un cookie HttpOnly
// gestito dal server (POST /auth/login setta il cookie, /auth/me lo
// verifica).  Un 401 su QUALSIASI chiamata API riporta alla vista di
// login (interceptor in fetchJSON).

function setUser(me) {
  currentUser = me;
  const userEl = document.getElementById("auth-user");
  if (userEl) {
    userEl.textContent = `${me.username} · ${me.role}`;
    userEl.hidden = false;
  }
  const logoutBtn = document.getElementById("logout-btn");
  const listsLink = document.getElementById("lists-link");
  const usersLink = document.getElementById("users-link");
  const refreshBtn = document.getElementById("refresh-btn");
  if (logoutBtn) logoutBtn.hidden = false;
  if (listsLink) listsLink.hidden = false;
  // La gestione utenti è SOLO admin: l'operatore non vede il link
  // (e il server risponde 403 se la vista viene forzata via hash)
  if (usersLink) usersLink.hidden = me.role !== "admin";
  if (refreshBtn) refreshBtn.hidden = false;
}

function clearUserUi() {
  currentUser = null;
  const userEl = document.getElementById("auth-user");
  const logoutBtn = document.getElementById("logout-btn");
  const listsLink = document.getElementById("lists-link");
  const usersLink = document.getElementById("users-link");
  const refreshBtn = document.getElementById("refresh-btn");
  if (userEl) userEl.hidden = true;
  if (logoutBtn) logoutBtn.hidden = true;
  if (listsLink) listsLink.hidden = true;
  if (usersLink) usersLink.hidden = true;
  if (refreshBtn) refreshBtn.hidden = true;
}

function showLoginNotice(kind, message) {
  const el = document.getElementById("login-notice");
  if (!el) return;
  el.className = `list-notice ${kind}`; // "success" | "error"
  el.textContent = message;
}

function showLogin(message) {
  stopPolling();
  clearUserUi();
  root.innerHTML = `
    <div class="login-card">
      <div class="login-title">Accedi alla dashboard</div>
      <form id="login-form" class="login-form">
        <input type="text" id="login-username" placeholder="Username" autocomplete="username" required />
        <input type="password" id="login-password" placeholder="Password" autocomplete="current-password" required />
        <button type="submit" id="login-btn">Accedi</button>
      </form>
      <div class="list-notice hidden" id="login-notice"></div>
    </div>`;
  document.getElementById("login-form").addEventListener("submit", onLoginSubmit);
  if (message) showLoginNotice("error", message);
  document.getElementById("login-username").focus();
}

async function onLoginSubmit(e) {
  e.preventDefault();
  const btn = document.getElementById("login-btn");
  btn.disabled = true;
  try {
    const me = await fetchJSON("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: document.getElementById("login-username").value.trim(),
        password: document.getElementById("login-password").value,
      }),
    });
    // Il browser processa il cookie di sessione in modo asincrono
    // (misurato: 300-400 ms dopo la risposta).  Se la home partisse
    // subito con le sue fetch, la prima senza cookie riceverebbe 401
    // e l'interceptor farebbe un auto-logout ingiustificato.  Si
    // attende che la sessione risulti attiva (poll su /auth/me) prima
    // di renderizzare.
    for (let i = 0; i < 40; i++) {
      try {
        const probe = await fetch("/auth/me");
        if (probe.ok) break;
      } catch (_) {
        /* rete assente: si riprova */
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    setUser(me);
    render(); // torna alla vista corrente (o elenco se hash vuoto)
  } catch (err) {
    showLoginNotice(
      "error",
      err.status === 401 ? err.message : `Accesso non riuscito: ${err.message}`
    );
    btn.disabled = false;
  }
}

document.getElementById("logout-btn").addEventListener("click", async () => {
  try {
    await fetchJSON("/auth/logout", { method: "POST" });
  } catch (_) {
    /* anche se la sessione è già scaduta, si torna al login */
  }
  showLogin();
  navigate("#/");
});

// ----------------------------------------------------------------- render

let listState = { limit: 20, offset: 0, status: "", classification: "", q: "" };
let listPollTimer = null;
let detailPollTimer = null;

// Selezione multipla: limitata alla PAGINA CORRENTE (mai a tutto il DB).
// Gli id selezionati sopravvivono ai re-render della stessa pagina
// (auto-refresh), ma vengono azzerati a ogni cambio pagina o filtro.
const selection = new Set();
let listNoticeTimer = null;

function stopPolling() {
  if (listPollTimer) { clearInterval(listPollTimer); listPollTimer = null; }
  if (detailPollTimer) { clearInterval(detailPollTimer); detailPollTimer = null; }
}

async function render() {
  stopPolling();
  if (!currentUser) {
    showLogin();
    return;
  }
  const route = currentRoute();
  if (route.name === "detail") {
    await renderDetail(route.id);
  } else if (route.name === "lists") {
    await renderLists();
  } else if (route.name === "users") {
    await renderUsers();
  } else {
    await renderList();
  }
}

// ------------------------------------------------------------- list view

function listSkeletonRows() {
  return Array.from({ length: 5 }).map(() => `<div class="skeleton"></div>`).join("");
}

async function renderList() {
  // Un solo passaggio: page-head + toolbar + UNICO container #sub-list
  // (con righe skeleton finché i dati non arrivano) + pager. Evita di
  // lasciare nel DOM un container skeleton "orfano" separato da quello
  // reale.
  root.innerHTML = `
    <div class="page-head">
      <div>
        <div class="page-title">Sottomissioni</div>
        <div class="page-hint">Tutte le analisi eseguite dal motore multilayer L0→L5</div>
      </div>
    </div>
    <div class="card submit-card">
      <form id="submit-form" class="submit-form">
        <div class="submit-row">
          <input type="text" id="submit-url" placeholder="https://… — incolla qui l'URL da analizzare"
                 autocomplete="off" spellcheck="false" />
          <button type="submit" id="submit-btn">Analizza</button>
        </div>
        <div class="submit-opts">
          <label class="submit-check">
            <input type="checkbox" id="submit-classify" checked />
            Classificazione L5 (Foundry)
          </label>
          <details class="submit-advanced">
            <summary>Budget di esplorazione</summary>
            <div class="submit-budget">
              <label>Profondità max
                <input type="number" id="submit-depth" min="1" max="20" placeholder="6" />
              </label>
              <label>Nodi max
                <input type="number" id="submit-nodes" min="1" max="200" placeholder="40" />
              </label>
              <label>Timeout (s)
                <input type="number" id="submit-timeout" min="10" max="3600" placeholder="180" />
              </label>
            </div>
          </details>
        </div>
      </form>
      <div class="list-notice hidden" id="submit-notice"></div>
    </div>
    <div class="toolbar">
      <div class="search-box">
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="11" cy="11" r="7"></circle><path d="m21 21-4.3-4.3"></path>
        </svg>
        <input type="text" id="search-input" placeholder="Cerca per URL…" value="${escapeHtml(listState.q)}" />
      </div>
      <select id="status-filter">
        <option value="">Tutti gli stati</option>
        <option value="queued">In coda</option>
        <option value="running">In corso</option>
        <option value="done">Completata</option>
        <option value="error">Errore</option>
      </select>
      <select id="cls-filter">
        <option value="">Tutte le classificazioni</option>
        <option value="benign">Benigno</option>
        <option value="suspicious">Sospetto</option>
        <option value="phishing">Phishing</option>
      </select>
    </div>
    <div class="list-actions">
      <label class="check-all-label">
        <input type="checkbox" id="check-all" />
        <span>seleziona tutti in questa pagina</span>
      </label>
      <span class="selection-count" id="selection-count">0 selezionate</span>
      <button class="btn-danger" id="delete-btn" disabled>Elimina</button>
    </div>
    <div class="list-notice hidden" id="list-notice"></div>
    <div class="sub-list" id="sub-list">${listSkeletonRows()}</div>
    <div class="pager" id="pager"></div>
  `;

  document.getElementById("status-filter").value = listState.status;
  document.getElementById("cls-filter").value = listState.classification;

  const onSearch = debounce((val) => {
    listState.q = val;
    listState.offset = 0;
    clearSelection(); // la selezione vale solo per la pagina mostrata
    loadAndRenderListBody().catch(() => {});
  }, 300);

  document.getElementById("search-input").addEventListener("input", (e) => onSearch(e.target.value));
  document.getElementById("status-filter").addEventListener("change", (e) => {
    listState.status = e.target.value;
    listState.offset = 0;
    clearSelection();
    loadAndRenderListBody().catch(() => {});
  });
  document.getElementById("cls-filter").addEventListener("change", (e) => {
    listState.classification = e.target.value;
    listState.offset = 0;
    clearSelection();
    loadAndRenderListBody().catch(() => {});
  });
  document.getElementById("check-all").addEventListener("click", () => {
    toggleAllOnPage();
  });
  document.getElementById("delete-btn").addEventListener("click", openDeleteDialog);

  // ── Form di sottomissione ─────────────────────────────────────────────
  // POST /analyses con gli stessi campi della CLI/API; se l'URL è in una
  // lista forzata la risposta arriva già "done" (bypass) e il messaggio
  // lo dichiara — altrimenti "queued" e il poll della lista la segue.
  document.getElementById("submit-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = document.getElementById("submit-url").value.trim();
    if (!url) {
      showSubmitNotice("error", "Inserisci un URL da analizzare.");
      return;
    }
    const btn = document.getElementById("submit-btn");
    btn.disabled = true;
    try {
      const payload = {
        url,
        classify: document.getElementById("submit-classify").checked,
      };
      const depth = document.getElementById("submit-depth").value;
      const nodes = document.getElementById("submit-nodes").value;
      const timeout = document.getElementById("submit-timeout").value;
      if (depth || nodes || timeout) {
        payload.budget = {};
        if (depth) payload.budget.max_depth = Number(depth);
        if (nodes) payload.budget.max_nodes = Number(nodes);
        if (timeout) payload.budget.timeout_s = Number(timeout);
      }
      const res = await fetchJSON("/analyses", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.status === "done") {
        showSubmitNotice(
          "success",
          `Lista forzata: verdetto immediato senza analisi. ` +
            `<a href="#/analyses/${res.id}">Apri il dettaglio</a>`
        );
      } else {
        showSubmitNotice(
          "success",
          `Analisi avviata. ` +
            `<a href="#/analyses/${res.id}">Segui il dettaglio</a>`
        );
      }
      document.getElementById("submit-url").value = "";
    } catch (err) {
      showSubmitNotice("error", `Sottomissione fallita: ${escapeHtml(err.message)}`);
    } finally {
      btn.disabled = false;
    }
    loadAndRenderListBody().catch(() => {});
  });

  try {
    await loadAndRenderListBody();
  } catch (e) {
    document.getElementById("sub-list").innerHTML =
      `<div class="error-state">Impossibile caricare le sottomissioni: ${escapeHtml(e.message)}</div>`;
    return;
  }

  // Auto-refresh leggero: solo se non si sta digitando nella ricerca
  listPollTimer = setInterval(() => {
    const searchFocused = document.activeElement?.id === "search-input";
    if (!searchFocused) loadAndRenderListBody().catch(() => {});
  }, 15000);
}

async function loadAndRenderListBody() {
  const params = new URLSearchParams({
    limit: listState.limit,
    offset: listState.offset,
  });
  if (listState.status) params.set("status", listState.status);
  if (listState.classification) params.set("classification", listState.classification);
  if (listState.q) params.set("q", listState.q);

  const data = await fetchJSON(`/analyses?${params.toString()}`);
  const listEl = document.getElementById("sub-list");
  const pagerEl = document.getElementById("pager");
  if (!listEl) return; // la vista è cambiata nel frattempo

  if (data.items.length === 0) {
    listEl.innerHTML = `<div class="empty-state">Nessuna sottomissione trovata.</div>`;
    pagerEl.innerHTML = "";
    pruneSelection();
    syncSelectionUi();
    return;
  }

  listEl.innerHTML = data.items
    .map((it) => {
      const url = it.input_url || "";
      const checked = selection.has(it.id);
      return `
      <div class="sub-row ${checked ? "selected" : ""}" data-id="${escapeHtml(it.id)}">
        <input type="checkbox" class="row-check" data-id="${escapeHtml(it.id)}" ${checked ? "checked" : ""} aria-label="Seleziona questa sottomissione" />
        <div class="sub-url">
          <span class="u" title="${escapeHtml(url)}">${escapeHtml(truncateMiddle(url, 70))}</span>
          <span class="h">${escapeHtml(it.id)}</span>
        </div>
        ${statusBadge(it.status)}
        ${classBadge(it.classification)}
        <span class="sub-counts">${it.num_states} stati · ${it.num_transitions} archi</span>
        <span class="sub-date">${formatDate(it.created_at)}</span>
        <svg class="chev" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
          <path d="m9 6 6 6-6 6"></path>
        </svg>
      </div>`;
    })
    .join("");

  listEl.querySelectorAll(".row-check").forEach((cb) => {
    cb.addEventListener("click", (e) => {
      // La checkbox non deve mai navigare al dettaglio
      e.stopPropagation();
      setSelected(cb.dataset.id, cb.checked);
    });
  });

  listEl.querySelectorAll(".sub-row").forEach((rowEl) => {
    rowEl.addEventListener("click", (e) => {
      if (e.target.closest(".row-check")) return;
      navigate(`#/analyses/${rowEl.dataset.id}`);
    });
  });

  pruneSelection();
  syncSelectionUi();

  const total = data.total;
  const from = data.offset + 1;
  const to = Math.min(data.offset + data.limit, total);
  pagerEl.innerHTML = `
    <button id="prev-page" ${data.offset === 0 ? "disabled" : ""}>← Precedenti</button>
    <span>${total === 0 ? 0 : from}–${to} di ${total}</span>
    <button id="next-page" ${to >= total ? "disabled" : ""}>Successivi →</button>
  `;
  document.getElementById("prev-page")?.addEventListener("click", () => {
    listState.offset = Math.max(0, listState.offset - listState.limit);
    clearSelection(); // nuova pagina → selezione azzerata
    loadAndRenderListBody().catch(() => {});
  });
  document.getElementById("next-page")?.addEventListener("click", () => {
    listState.offset += listState.limit;
    clearSelection();
    loadAndRenderListBody().catch(() => {});
  });
}

// ------------------------------------------------ selezione & eliminazione

function setSelected(id, checked) {
  if (checked) selection.add(id);
  else selection.delete(id);
  syncSelectionUi();
}

function clearSelection() {
  selection.clear();
  syncSelectionUi();
}

function toggleAllOnPage() {
  const rowChecks = [...document.querySelectorAll("#sub-list .row-check")];
  const allChecked =
    rowChecks.length > 0 && rowChecks.every((cb) => selection.has(cb.dataset.id));
  rowChecks.forEach((cb) => {
    if (allChecked) selection.delete(cb.dataset.id);
    else selection.add(cb.dataset.id);
    cb.checked = !allChecked;
  });
  syncSelectionUi();
}

/** Rimuove dalla selezione gli id non più visibili nella pagina corrente
 *  (es. righe sparite dopo un refresh): la selezione resta SEMPRE
 *  limitata a ciò che è mostrato. */
function pruneSelection() {
  const visible = new Set(
    [...document.querySelectorAll("#sub-list .row-check")].map((cb) => cb.dataset.id)
  );
  [...selection].forEach((id) => {
    if (!visible.has(id)) selection.delete(id);
  });
}

/** Allinea contatore, checkbox "seleziona tutti" e bottone Elimina. */
function syncSelectionUi() {
  const countEl = document.getElementById("selection-count");
  const checkAll = document.getElementById("check-all");
  const deleteBtn = document.getElementById("delete-btn");
  if (!countEl || !checkAll || !deleteBtn) return;

  const rowChecks = [...document.querySelectorAll("#sub-list .row-check")];
  const total = rowChecks.length;
  const n = rowChecks.filter((cb) => selection.has(cb.dataset.id)).length;

  countEl.textContent = n === 1 ? "1 selezionata" : `${n} selezionate`;
  deleteBtn.disabled = n === 0;
  deleteBtn.textContent =
    n === 0 ? "Elimina" : `Elimina ${n === 1 ? "sottomissione" : "sottomissioni"}`;

  checkAll.checked = total > 0 && n === total;
  checkAll.indeterminate = n > 0 && n < total;
  checkAll.disabled = total === 0;

  rowChecks.forEach((cb) => {
    const row = cb.closest(".sub-row");
    if (row) row.classList.toggle("selected", selection.has(cb.dataset.id));
  });
}

/** Banner di esito (successo/errore) nella vista elenco — si
 *  auto-nasconde dopo 8s. */
function showListNotice(type, text) {
  const el = document.getElementById("list-notice");
  if (!el) return;
  el.className = `list-notice ${type}`;
  el.textContent = text;
  clearTimeout(listNoticeTimer);
  listNoticeTimer = setTimeout(() => {
    el.className = "list-notice hidden";
    el.textContent = "";
  }, 8000);
}

// ------------------------------------------------ dialogo eliminazione

// Il dialogo vive FUORI da #view-root (document.body): sopravvive ai
// re-render delle viste e viene riutilizzato per tutta la sessione.
const deleteDialog = document.createElement("div");
deleteDialog.className = "modal-overlay hidden";
deleteDialog.innerHTML = `
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="delete-dialog-title">
    <div class="modal-title" id="delete-dialog-title">
      <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M3 6h18M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2m3 0-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"></path>
      </svg>
      Eliminazione definitiva
    </div>
    <div class="modal-body" id="delete-dialog-body"></div>
    <div class="modal-actions">
      <button class="btn-ghost" id="delete-cancel">Annulla</button>
      <button class="btn-danger" id="delete-confirm">Elimina definitivamente</button>
    </div>
  </div>`;
document.body.appendChild(deleteDialog);

let pendingDeleteIds = [];
let deleteBusy = false;

function openDeleteDialog() {
  if (selection.size === 0) return;
  pendingDeleteIds = [...selection];
  const n = pendingDeleteIds.length;
  document.getElementById("delete-dialog-body").innerHTML =
    `Stai per eliminare definitivamente <b>${n} sottomission${n === 1 ? "e" : "i"}</b>.` +
    `<span class="irreversible">⚠ Azione IRREVERSIBILE — le righe verranno rimosse dal database e i relativi artefatti cancellati dal disco. Non sarà possibile recuperarli.</span>`;
  deleteDialog.classList.remove("hidden");
  document.getElementById("delete-confirm").focus();
}

function closeDeleteDialog() {
  if (deleteBusy) return; // durante la POST il dialogo non si chiude
  deleteDialog.classList.add("hidden");
}

function forceCloseDeleteDialog() {
  deleteDialog.classList.add("hidden");
}

document.getElementById("delete-cancel").addEventListener("click", closeDeleteDialog);
deleteDialog.addEventListener("click", (e) => {
  if (e.target === deleteDialog) closeDeleteDialog();
});

document.getElementById("delete-confirm").addEventListener("click", async () => {
  if (deleteBusy || pendingDeleteIds.length === 0) return;
  deleteBusy = true;
  const confirmBtn = document.getElementById("delete-confirm");
  confirmBtn.disabled = true;
  confirmBtn.textContent = "Eliminazione…";

  let deleted = false;
  try {
    const res = await fetch("/analyses/delete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ids: pendingDeleteIds }),
    });
    let data = null;
    try { data = await res.json(); } catch (_) { /* risposta non JSON */ }
    if (!res.ok) {
      const detail = (data && data.detail) || res.statusText;
      throw new Error(detail);
    }

    deleted = true;
    selection.clear();
    forceCloseDeleteDialog();

    let msg = `Eliminate ${data.deleted_count} sottomission${data.deleted_count === 1 ? "e" : "i"}.`;
    if (data.not_found && data.not_found.length > 0) {
      msg += ` Non trovate: ${data.not_found.length}.`;
    }
    showListNotice("success", msg);
  } catch (e) {
    forceCloseDeleteDialog();
    showListNotice("error", `Eliminazione non riuscita: ${e.message}`);
  } finally {
    deleteBusy = false;
    confirmBtn.disabled = false;
    confirmBtn.textContent = "Elimina definitivamente";
  }

  // Ricarica la lista; un eventuale errore di reload non deve
  // sovrascrivere il messaggio d'errore della POST fallita
  loadAndRenderListBody().catch(() => {
    if (deleted) {
      showListNotice(
        "error",
        "Eliminazione completata, ma la lista non si è aggiornata — ricarica la pagina."
      );
    }
  });
});

// ------------------------------------------------------------ lists view
// Whitelist/blacklist forzate (domini e URL) — vista #/lists.
// Il match avviene sul dominio registrabile o sulla URL normalizzata
// senza query/frammento; la URL (più specifica) vince sul dominio.

function listBadge(listType) {
  return listType === "whitelist"
    ? `<span class="badge cls-benign">Whitelist</span>`
    : `<span class="badge cls-phishing">Blacklist</span>`;
}

function listRowsHtml(entries, kind) {
  if (!entries.length) {
    return `<div class="empty-state">Nessun ${kind === "domain" ? "dominio" : "URL"} in lista.</div>`;
  }
  return entries
    .map((en) => {
      const meta = [
        en.note ? escapeHtml(en.note) : null,
        en.added_by ? `da ${escapeHtml(en.added_by)}` : null,
        en.added_at ? formatDate(en.added_at) : null,
      ]
        .filter(Boolean)
        .join(" · ");
      return `
      <div class="list-row">
        <div class="list-row-main">
          <span class="u" title="${escapeHtml(en.value)}">${escapeHtml(truncateMiddle(en.value, 90))}</span>
          ${meta ? `<span class="h">${meta}</span>` : ""}
        </div>
        ${listBadge(en.list_type)}
        <button class="list-remove" data-kind="${escapeHtml(kind)}" data-value="${escapeHtml(en.value)}"
                title="Rimuovi dalla lista" aria-label="Rimuovi dalla lista">✕</button>
      </div>`;
    })
    .join("");
}

function showListsNotice(kind, message) {
  const el = document.getElementById("lists-notice");
  if (!el) return;
  el.className = `list-notice ${kind}`; // "success" | "error"
  el.textContent = message;
}

function showSubmitNotice(kind, message) {
  // Come showListsNotice ma con innerHTML (il messaggio di successo
  // contiene il link al dettaglio; l'unico dato dinamico è l'id UUID
  // restituito dal server, non input dell'utente).
  const el = document.getElementById("submit-notice");
  if (!el) return;
  el.className = `list-notice ${kind}`;
  el.innerHTML = message;
}

async function loadListsBody() {
  const data = await fetchJSON("/lists");
  const domEl = document.getElementById("domain-rows");
  const urlEl = document.getElementById("url-rows");
  const domCount = document.getElementById("domain-count");
  const urlCount = document.getElementById("url-count");
  if (!domEl || !urlEl) return; // la vista è cambiata nel frattempo
  domCount.textContent = String(data.domains.length);
  urlCount.textContent = String(data.urls.length);
  domEl.innerHTML = listRowsHtml(data.domains, "domain");
  urlEl.innerHTML = listRowsHtml(data.urls, "url");
  document.querySelectorAll(".list-remove").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const value = btn.dataset.value;
      const kind = btn.dataset.kind;
      if (!window.confirm(`Rimuovere "${value}" dalla ${kind === "url" ? "lista URL" : "lista domini"}?`)) {
        return;
      }
      try {
        await fetchJSON("/lists", {
          method: "DELETE",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ kind, value }),
        });
        showListsNotice("success", `Rimosso: ${value}`);
      } catch (err) {
        showListsNotice("error", `Rimozione fallita: ${err.message}`);
        return;
      }
      await loadListsBody().catch(() => {});
    });
  });
}

async function renderLists() {
  root.innerHTML = `
    <div class="page-head">
      <div>
        <div class="page-title">Whitelist / Blacklist</div>
        <div class="page-hint">Forza la reputazione di un dominio o di una URL: l'analisi viene bypassata e Trellix riceve il verdetto forzato</div>
      </div>
    </div>
    <button class="back-link" id="back-link">
      <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M19 12H5m6-6-6 6 6 6"></path>
      </svg>
      Torna alle sottomissioni
    </button>

    <div class="card lists-form-card">
      <form id="lists-add-form" class="lists-form">
        <select id="add-kind" aria-label="Tipo di voce">
          <option value="url">URL</option>
          <option value="domain">Dominio</option>
        </select>
        <input type="text" id="add-value" placeholder="https://sito.it/pagina oppure sito.it"
               autocomplete="off" spellcheck="false" />
        <select id="add-list-type" aria-label="Lista">
          <option value="whitelist">Whitelist</option>
          <option value="blacklist">Blacklist</option>
        </select>
        <input type="text" id="add-note" placeholder="Nota (facoltativa)" autocomplete="off" />
        <button type="submit" id="add-btn">Aggiungi</button>
      </form>
      <div class="list-notice hidden" id="lists-notice"></div>
    </div>

    <div class="lists-grid">
      <div class="card list-card">
        <div class="list-card-head">Domini <span class="count-pill" id="domain-count">…</span></div>
        <div class="list-hint">Match sul dominio registrabile (eTLD+1): "login.sito.it" è coperto da "sito.it"</div>
        <div id="domain-rows"><div class="skeleton"></div></div>
      </div>
      <div class="card list-card">
        <div class="list-card-head">URL <span class="count-pill" id="url-count">…</span></div>
        <div class="list-hint">Match sulla URL normalizzata senza query/frammento — più specifica, vince sul dominio</div>
        <div id="url-rows"><div class="skeleton"></div></div>
      </div>
    </div>
  `;

  document.getElementById("back-link").addEventListener("click", () => navigate("#/"));

  document.getElementById("lists-add-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const kind = document.getElementById("add-kind").value;
    const value = document.getElementById("add-value").value.trim();
    const listType = document.getElementById("add-list-type").value;
    const note = document.getElementById("add-note").value.trim() || null;
    if (!value) {
      showListsNotice("error", "Inserisci un dominio o una URL.");
      return;
    }
    try {
      const res = await fetchJSON("/lists", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ kind, value, list_type: listType, note }),
      });
      showListsNotice(
        "success",
        `Aggiunto: ${res.value} → ${res.list_type === "whitelist" ? "whitelist" : "blacklist"}` +
          (res.value !== value ? " (normalizzato)" : "")
      );
      document.getElementById("add-value").value = "";
      document.getElementById("add-note").value = "";
    } catch (err) {
      showListsNotice("error", `Aggiunta fallita: ${err.message}`);
      return;
    }
    await loadListsBody().catch(() => {});
  });

  try {
    await loadListsBody();
  } catch (e) {
    document.getElementById("domain-rows").innerHTML =
      document.getElementById("url-rows").innerHTML =
        `<div class="error-state">Impossibile caricare le liste: ${escapeHtml(e.message)}</div>`;
  }
}

// ------------------------------------------------------------ users view
// Gestione degli utenti della dashboard — vista #/users, SOLO admin.
// L'operatore non vede il link in topbar; se forza l'hash, la vista
// mostra un errore (e il server risponde 403 a ogni chiamata).

function roleBadge(role) {
  return role === "admin"
    ? `<span class="badge role-admin">admin</span>`
    : `<span class="badge role-operator">operator</span>`;
}

function showUsersNotice(kind, message) {
  const el = document.getElementById("users-notice");
  if (!el) return;
  el.className = `list-notice ${kind}`; // "success" | "error"
  el.textContent = message;
}

function userRowsHtml(users) {
  if (!users.length) {
    return `<div class="empty-state">Nessun utente — crea il primo.</div>`;
  }
  return users
    .map((u) => {
      const isMe = u.username === currentUser.username;
      return `
      <div class="list-row user-row">
        <div class="list-row-main">
          <span class="u">${escapeHtml(u.username)}${isMe ? ` <span class="h">(tu)</span>` : ""}</span>
          <span class="h">creato il ${formatDate(u.created_at)}</span>
        </div>
        ${roleBadge(u.role)}
        <select class="user-role" data-username="${escapeHtml(u.username)}"
                aria-label="Ruolo di ${escapeHtml(u.username)}">
          <option value="operator" ${u.role === "operator" ? "selected" : ""}>operator</option>
          <option value="admin" ${u.role === "admin" ? "selected" : ""}>admin</option>
        </select>
        <button class="user-pass-btn" data-username="${escapeHtml(u.username)}" type="button">Password…</button>
        <button class="list-remove" data-username="${escapeHtml(u.username)}" type="button"
                title="${isMe ? "Non puoi eliminare il tuo account" : "Elimina utente"}"
                aria-label="Elimina utente" ${isMe ? "disabled" : ""}>✕</button>
        <div class="user-pass-form hidden">
          <input type="password" class="user-pass-input" placeholder="Nuova password (min 8)"
                 autocomplete="new-password" />
          <button class="user-pass-ok" type="button">Salva</button>
          <button class="user-pass-cancel" type="button">Annulla</button>
        </div>
      </div>`;
    })
    .join("");
}

async function loadUsersBody() {
  const data = await fetchJSON("/auth/users");
  const rowsEl = document.getElementById("user-rows");
  const countEl = document.getElementById("user-count");
  if (!rowsEl) return; // la vista è cambiata nel frattempo
  countEl.textContent = String(data.users.length);
  rowsEl.innerHTML = userRowsHtml(data.users);

  // ── Cambio ruolo (PATCH) ────────────────────────────────────────────
  rowsEl.querySelectorAll(".user-role").forEach((sel) => {
    sel.addEventListener("change", async () => {
      const username = sel.dataset.username;
      const newRole = sel.value;
      // Degradare se stessi revoca la propria sessione → logout forzato
      if (username === currentUser.username && newRole !== "admin") {
        const ok = window.confirm(
          "Cambiando il TUO ruolo a operator perderai l'accesso alla gestione " +
            "utenti e dovrai accedere di nuovo. Continuare?"
        );
        if (!ok) {
          sel.value = "admin";
          return;
        }
      }
      try {
        await fetchJSON(`/auth/users/${encodeURIComponent(username)}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ role: newRole }),
        });
        showUsersNotice(
          "success",
          username === currentUser.username && newRole !== "admin"
            ? `Ruolo aggiornato — ora sei operator: devi accedere di nuovo.`
            : `Ruolo di ${username} aggiornato: ${newRole}.`
        );
      } catch (err) {
        showUsersNotice("error", `Aggiornamento non riuscito: ${err.message}`);
        return;
      }
      // Il reload può fallire con 401 se ci si è degradati da soli:
      // l'interceptor mostra il login, che è il comportamento giusto.
      await loadUsersBody().catch(() => {});
    });
  });

  // ── Nuova password (PATCH) — form inline per riga ───────────────────
  rowsEl.querySelectorAll(".user-pass-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const row = btn.closest(".list-row");
      const form = row.querySelector(".user-pass-form");
      const wasHidden = form.classList.contains("hidden");
      // Chiude gli eventuali altri form aperti prima di aprirne uno nuovo
      rowsEl.querySelectorAll(".user-pass-form").forEach((f) => {
        f.classList.add("hidden");
        f.querySelector(".user-pass-input").value = "";
      });
      if (wasHidden) {
        form.classList.remove("hidden");
        form.querySelector(".user-pass-input").focus();
      }
    });
  });
  rowsEl.querySelectorAll(".user-pass-ok").forEach((okBtn) => {
    okBtn.addEventListener("click", async () => {
      const row = okBtn.closest(".list-row");
      const username = row.querySelector(".user-role").dataset.username;
      const input = row.querySelector(".user-pass-input");
      const password = input.value;
      if (password.length < 8) {
        showUsersNotice("error", "La password deve avere almeno 8 caratteri.");
        return;
      }
      try {
        await fetchJSON(`/auth/users/${encodeURIComponent(username)}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password }),
        });
        showUsersNotice(
          "success",
          `Password di ${username} aggiornata.` +
            (username === currentUser.username ? " Dovrai accedere di nuovo." : "")
        );
      } catch (err) {
        showUsersNotice("error", `Aggiornamento non riuscito: ${err.message}`);
        return;
      }
      await loadUsersBody().catch(() => {});
    });
  });
  rowsEl.querySelectorAll(".user-pass-cancel").forEach((btn) => {
    btn.addEventListener("click", () => {
      const row = btn.closest(".list-row");
      row.querySelector(".user-pass-form").classList.add("hidden");
      row.querySelector(".user-pass-input").value = "";
    });
  });

  // ── Eliminazione (DELETE) ───────────────────────────────────────────
  rowsEl.querySelectorAll(".list-remove").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const username = btn.dataset.username;
      if (!window.confirm(`Eliminare l'utente "${username}"? L'azione è irreversibile.`)) {
        return;
      }
      try {
        await fetchJSON(`/auth/users/${encodeURIComponent(username)}`, {
          method: "DELETE",
        });
        showUsersNotice("success", `Utente eliminato: ${username}`);
      } catch (err) {
        showUsersNotice("error", `Eliminazione non riuscita: ${err.message}`);
        return;
      }
      await loadUsersBody().catch(() => {});
    });
  });
}

async function renderUsers() {
  if (!currentUser || currentUser.role !== "admin") {
    root.innerHTML = `<div class="error-state">Richiede ruolo admin.</div>`;
    return;
  }
  root.innerHTML = `
    <div class="page-head">
      <div>
        <div class="page-title">Gestione utenti</div>
        <div class="page-hint">Chi può accedere alla dashboard: ruoli admin/operator, password con hash PBKDF2 in SQLite</div>
      </div>
    </div>
    <button class="back-link" id="back-link">
      <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M19 12H5m6-6-6 6 6 6"></path>
      </svg>
      Torna alle sottomissioni
    </button>

    <div class="card lists-form-card">
      <form id="user-add-form" class="lists-form">
        <input type="text" id="add-username" placeholder="Username" autocomplete="off" spellcheck="false" />
        <input type="password" id="add-password" placeholder="Password (min 8 caratteri)" autocomplete="new-password" />
        <select id="add-role" aria-label="Ruolo del nuovo utente">
          <option value="operator">operator</option>
          <option value="admin">admin</option>
        </select>
        <button type="submit" id="add-user-btn">Crea utente</button>
      </form>
      <div class="list-notice hidden" id="users-notice"></div>
    </div>

    <div class="card list-card">
      <div class="list-card-head">Utenti <span class="count-pill" id="user-count">…</span></div>
      <div class="list-hint">La sessione vive in un cookie HttpOnly di 12h; cambiare password o ruolo revoca le sessioni attive dell'utente</div>
      <div id="user-rows"><div class="skeleton"></div></div>
    </div>
  `;

  document.getElementById("back-link").addEventListener("click", () => navigate("#/"));

  document.getElementById("user-add-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = document.getElementById("add-username").value.trim();
    const password = document.getElementById("add-password").value;
    const role = document.getElementById("add-role").value;
    if (!username) {
      showUsersNotice("error", "Inserisci uno username.");
      return;
    }
    if (password.length < 8) {
      showUsersNotice("error", "La password deve avere almeno 8 caratteri.");
      return;
    }
    try {
      await fetchJSON("/auth/users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password, role }),
      });
      showUsersNotice("success", `Utente creato: ${username} (${role}).`);
      document.getElementById("add-username").value = "";
      document.getElementById("add-password").value = "";
    } catch (err) {
      showUsersNotice("error", `Creazione fallita: ${err.message}`);
      return;
    }
    await loadUsersBody().catch(() => {});
  });

  try {
    await loadUsersBody();
  } catch (e) {
    document.getElementById("user-rows").innerHTML =
      `<div class="error-state">Impossibile caricare gli utenti: ${escapeHtml(e.message)}</div>`;
  }
}

// ----------------------------------------------------------- detail view

async function renderDetail(id) {
  // Un solo back-link, dentro il markup prodotto da buildDetailHtml —
  // niente elementi duplicati tra lo stato di caricamento e quello finale.
  root.innerHTML = `<button class="back-link" id="back-link">← Torna alle sottomissioni</button><div class="loading-state">Caricamento analisi…</div>`;
  document.getElementById("back-link").addEventListener("click", () => navigate("#/"));

  let graph, artifacts, trellix;
  try {
    [graph, artifacts, trellix] = await Promise.all([
      fetchJSON(`/analyses/${id}/graph`),
      fetchJSON(`/analyses/${id}/artifacts`).catch(() => ({ files: [] })),
      fetchJSON(`/analyses/${id}/trellix`).catch(() => null),
    ]);
  } catch (e) {
    root.querySelector(".loading-state").outerHTML =
      `<div class="error-state">Impossibile caricare l'analisi (${escapeHtml(e.message)}).</div>`;
    return;
  }

  root.innerHTML = buildDetailHtml(id, graph, artifacts, trellix);
  wireDetail(id, graph);

  // Se l'analisi è ancora in corso, ricontrolla periodicamente
  if (graph.target.status === "queued" || graph.target.status === "running") {
    detailPollTimer = setInterval(async () => {
      try {
        const fresh = await fetchJSON(`/analyses/${id}/graph`);
        if (fresh.target.status !== "queued" && fresh.target.status !== "running") {
          clearInterval(detailPollTimer);
        }
        const freshArtifacts = await fetchJSON(`/analyses/${id}/artifacts`).catch(() => ({ files: [] }));
        const freshTrellix = await fetchJSON(`/analyses/${id}/trellix`).catch(() => null);
        root.innerHTML = buildDetailHtml(id, fresh, freshArtifacts, freshTrellix);
        wireDetail(id, fresh);
      } catch (_) {
        /* riprova al prossimo tick */
      }
    }, 6000);
  }
}

function buildDetailHtml(id, graph, artifacts, trellix) {
  const t = graph.target;
  const v = graph.verdict;
  const states = graph.states || [];
  const transitions = graph.transitions || [];
  const evidence = graph.evidence || [];

  const incomingKind = {};
  transitions.forEach((tr) => { incomingKind[tr.to_state] = tr.kind; });

  const fileSet = new Set((artifacts.files || []).map((f) => f.path));

  return `
    <button class="back-link" id="back-link">← Torna alle sottomissioni</button>

    <div class="card detail-head">
      <div class="detail-urls">
        <span class="url-in">${escapeHtml(t.input_url)}</span>
        ${t.final_url && t.final_url !== t.input_url ? `<span class="url-arrow">→</span><span class="url-final">${escapeHtml(t.final_url)}</span>` : ""}
      </div>
      <div class="detail-badges">
        ${statusBadge(t.status)}
        ${classBadge(v?.classification)}
        ${v ? `
          <div class="confidence-wrap">
            <div class="confidence-track"><div class="confidence-fill" style="width:${Math.round((v.confidence || 0) * 100)}%"></div></div>
            <span class="confidence-num">${Math.round((v.confidence || 0) * 100)}% confidenza</span>
          </div>` : ""}
        ${v?.brand ? `<span class="badge cls-none">brand: ${escapeHtml(v.brand)}</span>` : ""}
        ${v?.kit_family ? `<span class="badge cls-none">kit: ${escapeHtml(v.kit_family)}</span>` : ""}
      </div>
      <div class="meta-row">
        <span>ID: <b>${escapeHtml(t.id)}</b></span>
        <span>Creata: <b>${formatDate(t.created_at)}</b></span>
        <span>Verdetto da: <b>${escapeHtml(v?.produced_by || "—")}</b></span>
        <span>Stati: <b>${states.length}</b></span>
        <span>Transizioni: <b>${transitions.length}</b></span>
      </div>
      ${v?.rationale ? `<div class="rationale"><b>Motivazione:</b> ${escapeHtml(v.rationale)}</div>` : ""}
    </div>

    ${trellix ? `
    <div class="section">
      <div class="section-title">Risposta restituita a Trellix IVX</div>
      <div class="card trellix-box">
        <div class="trellix-head">
          <span class="trellix-verdict trellix-${escapeHtml(trellix.result.verdict)}">${escapeHtml(trellix.result.verdict)}</span>
          <button class="btn-copy" id="copy-trellix-btn" type="button">Copia JSON</button>
        </div>
        <pre class="trellix-json" id="trellix-json">${escapeHtml(JSON.stringify(trellix, null, 2))}</pre>
      </div>
    </div>` : ""}

    ${states.length > 0 ? `
    <div class="section">
      <div class="section-title">Grafo di esplorazione <span class="count-pill">${states.length} nodi · ${transitions.length} archi</span></div>
      <div class="card graph-card">${buildGraphSvg(states, transitions)}</div>
    </div>` : ""}

    ${states.length > 0 ? `
    <div class="section">
      <div class="section-title">Stati catturati</div>
      <div class="states-grid">
        ${states.map((s) => buildStateCard(id, s, incomingKind[s.id], fileSet)).join("")}
      </div>
    </div>` : ""}

    <div class="section">
      <div class="section-title">Evidenze <span class="count-pill">${evidence.length}</span></div>
      ${evidence.length === 0 ? `<div class="empty-state">Nessuna evidenza registrata.</div>` : buildEvidenceAccordion(evidence)}
    </div>
  `;
}

function buildStateCard(targetId, state, incomingKind, fileSet) {
  const shotPath = `${state.id}/screenshot.png`;
  const hasShot = fileSet.has(shotPath);
  const shotUrl = artifactUrl(targetId, state.id, "screenshot.png");
  const domPath = `${state.id}/dom.html`;
  const harPath = `${state.id}/snapshot.har`;

  return `
    <div class="state-card" id="state-card-${escapeHtml(state.id)}">
      <div class="state-thumb">
        <span class="state-depth-pill">${incomingKind ? escapeHtml(TRANSITION_LABELS[incomingKind] || incomingKind) + " · " : ""}profondità ${state.depth}</span>
        ${hasShot
          ? `<img src="${shotUrl}" loading="lazy" alt="Screenshot dello stato" data-full="${shotUrl}" />`
          : `<span class="no-shot">nessuno screenshot</span>`}
      </div>
      <div class="state-body">
        <div class="state-url" title="${escapeHtml(state.url)}">${escapeHtml(truncateMiddle(state.url, 90))}</div>
        <div class="state-hash">dom_hash ${escapeHtml((state.dom_hash || "").slice(0, 16))}…</div>
        <div class="state-links">
          ${fileSet.has(domPath) ? `<a href="${artifactUrl(targetId, state.id, "dom.html")}" target="_blank" rel="noopener">DOM</a>` : ""}
          ${fileSet.has(harPath) ? `<a href="${artifactUrl(targetId, state.id, "snapshot.har")}" target="_blank" rel="noopener">HAR</a>` : ""}
        </div>
      </div>
    </div>`;
}

function buildEvidenceAccordion(evidence) {
  const groups = {};
  evidence.forEach((e) => {
    const layer = e.layer || "?";
    (groups[layer] = groups[layer] || []).push(e);
  });

  const layers = Object.keys(groups).sort((a, b) => {
    const ia = LAYER_ORDER.indexOf(a);
    const ib = LAYER_ORDER.indexOf(b);
    if (ia === -1 && ib === -1) return a.localeCompare(b);
    if (ia === -1) return 1;
    if (ib === -1) return -1;
    return ia - ib;
  });

  return layers
    .map((layer) => {
      const rows = groups[layer]
        .map(
          (e) => `
        <tr>
          <td class="key">${escapeHtml(e.key)}</td>
          <td class="val">${escapeHtml(truncateMiddle(String(e.value), 300))}</td>
          <td><span class="weight-chip ${weightChipClass(e.weight)}">${Number(e.weight).toFixed(2)}</span></td>
          <td class="by">${escapeHtml(e.produced_by)}</td>
        </tr>`
        )
        .join("");
      return `
      <details class="evidence-layer">
        <summary>
          <span><span class="layer-tag">${escapeHtml(layer)}</span>${groups[layer].length} evidenz${groups[layer].length === 1 ? "a" : "e"}</span>
          <svg class="chev" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="m9 6 6 6-6 6"></path></svg>
        </summary>
        <table class="evidence-table">
          <thead><tr><th>Chiave</th><th>Valore</th><th>Peso</th><th>Prodotta da</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </details>`;
    })
    .join("");
}

// --------------------------------------------------------------- graph svg
//
// Layout a colonne per profondità (layer by depth) con:
//  - colonne larghe quanto il testo più lungo → mai sovrapposte,
//  - ordinamento barycenter (sweep avanti/indietro) per ridurre gli
//    incroci degli archi,
//  - archi verticali (stessa colonna, es. cloaking_probe tra i due
//    root) deviati lateralmente per non attraversare i nodi,
//  - etichette degli archi scaglionate quando più archi convergono
//    sullo stesso punto medio.

const GRAPH = {
  nodeR: 7,
  labelDx: 12, // offset del testo dal centro del nodo
  colGap: 90, // spazio libero tra il testo e la colonna successiva
  rowGap: 56, // distanza verticale tra i nodi di una colonna
  margin: 30,
  charW: 6.4, // larghezza media di un carattere mono 10px
  maxLabelChars: 24,
  bend: 45, // deviazione laterale degli archi verticali
};

function truncateHost(url) {
  return truncateMiddle(String(url || "").replace(/^https?:\/\//, ""), GRAPH.maxLabelChars);
}

function orderColumns(byDepth, depths, transitions) {
  // Barycenter sweep: ordina ogni colonna per la posizione media dei
  // vicini nella colonna adiacente; 4 passate (avanti/indietro)
  // stabilizzano anche grafi con molti archi incrociati.  I nodi senza
  // vicini restano al proprio posto (sort stabile).
  const adj = new Map();
  const add = (a, b) => {
    if (!adj.has(a)) adj.set(a, []);
    adj.get(a).push(b);
  };
  transitions.forEach((t) => {
    add(t.from_state, t.to_state);
    add(t.to_state, t.from_state);
  });

  for (let pass = 0; pass < 4; pass++) {
    const dir = pass % 2 === 0 ? 1 : -1;
    const sweep = dir === 1
      ? depths.map((_, i) => i)
      : depths.map((_, i) => depths.length - 1 - i);
    for (const ci of sweep) {
      const nd = depths[ci + dir];
      if (nd === undefined) continue;
      const neighborIdx = new Map(byDepth[nd].map((s, i) => [s.id, i]));
      const col = byDepth[depths[ci]];
      const avg = col.map((s, i) => {
        const ns = (adj.get(s.id) || [])
          .map((n) => neighborIdx.get(n))
          .filter((x) => x !== undefined);
        return ns.length ? ns.reduce((a, b) => a + b, 0) / ns.length : i;
      });
      byDepth[depths[ci]] = col
        .map((s, i) => ({ s, avg: avg[i], i }))
        .sort((a, b) => a.avg - b.avg || a.i - b.i)
        .map((o) => o.s);
    }
  }
}

function buildGraphSvg(states, transitions) {
  const byDepth = {};
  states.forEach((s) => {
    (byDepth[s.depth] = byDepth[s.depth] || []).push(s);
  });
  const depths = Object.keys(byDepth).map(Number).sort((a, b) => a - b);
  if (!depths.length) return "";

  orderColumns(byDepth, depths, transitions);

  // Larghezza per colonna: il testo più lungo + spazio per la colonna
  // successiva.  Le coordinate X partono dal margine e accumulano.
  const colW = depths.map((d) => (
    Math.max(...byDepth[d].map((s) => truncateHost(s.url).length), 8) * GRAPH.charW + GRAPH.colGap
  ));
  const colX = [GRAPH.margin];
  depths.forEach((_, i) => {
    if (i > 0) colX.push(colX[i - 1] + colW[i - 1]);
  });

  const pos = {};
  depths.forEach((d, ci) => {
    byDepth[d].forEach((s, ri) => {
      pos[s.id] = {
        x: colX[ci] + GRAPH.labelDx,
        y: GRAPH.margin + ri * GRAPH.rowGap,
        col: ci,
      };
    });
  });

  const maxRows = Math.max(...depths.map((d) => byDepth[d].length), 1);
  const width = colX[depths.length - 1] + colW[depths.length - 1];
  const height = GRAPH.margin * 2 + (maxRows - 1) * GRAPH.rowGap + GRAPH.nodeR + 4;

  const outgoing = new Set(transitions.map((t) => t.from_state));

  // Slot per le etichette: archi con lo stesso punto medio vengono
  // scaglionati in verticale invece di sovrapporsi.
  const labelSlots = new Map();
  const slotFor = (x, y) => {
    const key = `${Math.round(x / 12)}:${Math.round(y / 12)}`;
    const n = labelSlots.get(key) || 0;
    labelSlots.set(key, n + 1);
    return n;
  };

  // Coppie di colonne DENSE (oltre _DENSE_PAIR_THRESHOLD archi):
  // etichetta SOLO un arco per tipo — ripetere "3xx" decine di volte
  // non aggiunge informazione, solo rumore.  Il <title> resta su ogni
  // arco (visibile al passaggio del mouse).  Il caso reale
  // dell'explorer (~1 arco per nodo) resta sempre completo.
  const _DENSE_PAIR_THRESHOLD = 4;
  const pairTotals = new Map();
  transitions.forEach((t) => {
    const a = pos[t.from_state];
    const b = pos[t.to_state];
    if (!a || !b || Math.abs(a.x - b.x) < 1) return;
    const key = `${a.col}-${b.col}`;
    pairTotals.set(key, (pairTotals.get(key) || 0) + 1);
  });
  const labeledKinds = new Set();

  const edgesSvg = transitions
    .map((t) => {
      const a = pos[t.from_state];
      const b = pos[t.to_state];
      if (!a || !b) return "";
      const label = TRANSITION_LABELS[t.kind] || t.kind;
      if (Math.abs(a.x - b.x) < 1) {
        // Arco verticale (stessa colonna): curva deviata a destra, label
        // sul lato — attraversare la colonna renderebbe il grafo
        // illeggibile (caso reale: cloaking_probe tra i due root).
        const midY = (a.y + b.y) / 2;
        const path = `M ${a.x} ${a.y} C ${a.x + GRAPH.bend} ${a.y}, ${b.x + GRAPH.bend} ${b.y}, ${b.x} ${b.y}`;
        return `<path class="graph-edge" d="${path}"><title>${escapeHtml(t.kind)}</title></path>
                <text class="graph-edge-label" x="${a.x + GRAPH.bend + 6}" y="${midY + 3}">${escapeHtml(label)}</text>`;
      }
      const midX = (a.x + b.x) / 2;
      const midY = (a.y + b.y) / 2;
      const pairKey = `${a.col}-${b.col}`;
      const dense = (pairTotals.get(pairKey) || 0) > _DENSE_PAIR_THRESHOLD;
      const kindKey = `${pairKey}:${label}`;
      const off = slotFor(midX, midY) * 10;
      const path = `M ${a.x} ${a.y} C ${midX} ${a.y}, ${midX} ${b.y}, ${b.x} ${b.y}`;
      let labelSvg = "";
      if (!dense || !labeledKinds.has(kindKey)) {
        labeledKinds.add(kindKey);
        labelSvg = `<text class="graph-edge-label" x="${midX}" y="${midY - 4 - off}" text-anchor="middle">${escapeHtml(label)}</text>`;
      }
      return `<path class="graph-edge" d="${path}"><title>${escapeHtml(t.kind)}</title></path>${labelSvg}`;
    })
    .join("");

  const nodesSvg = states
    .map((s) => {
      const p = pos[s.id];
      if (!p) return "";
      const isLeaf = !outgoing.has(s.id);
      return `
        <g class="graph-node${isLeaf ? " leaf" : ""}" data-id="${escapeHtml(s.id)}" transform="translate(${p.x},${p.y})">
          <title>${escapeHtml(s.url)}</title>
          <circle r="${GRAPH.nodeR}"></circle>
          <text x="${GRAPH.nodeR + 5}" y="4">${escapeHtml(truncateHost(s.url))}</text>
        </g>`;
    })
    .join("");

  return `<svg viewBox="0 0 ${width} ${height}" width="${width}" height="${height}">${edgesSvg}${nodesSvg}</svg>`;
}

function wireDetail(targetId, graph) {
  document.getElementById("back-link")?.addEventListener("click", () => navigate("#/"));

  const copyBtn = document.getElementById("copy-trellix-btn");
  if (copyBtn) {
    copyBtn.addEventListener("click", async () => {
      const pre = document.getElementById("trellix-json");
      if (!pre) return;
      const text = pre.textContent;
      let ok = false;
      try {
        await navigator.clipboard.writeText(text);
        ok = true;
      } catch (_) {
        // Fallback per contesti senza Clipboard API
        try {
          const ta = document.createElement("textarea");
          ta.value = text;
          document.body.appendChild(ta);
          ta.select();
          ok = document.execCommand("copy");
          ta.remove();
        } catch (_) {
          /* lascia il bottone invariato */
        }
      }
      if (ok) {
        copyBtn.textContent = "Copiato ✓";
        setTimeout(() => { copyBtn.textContent = "Copia JSON"; }, 1500);
      }
    });
  }

  root.querySelectorAll(".state-thumb img").forEach((img) => {
    img.addEventListener("click", () => openLightbox(img.dataset.full));
  });

  root.querySelectorAll(".graph-node").forEach((node) => {
    node.addEventListener("click", () => {
      const card = document.getElementById(`state-card-${node.dataset.id}`);
      if (!card) return;
      card.scrollIntoView({ behavior: "smooth", block: "center" });
      card.style.transition = "box-shadow 0.2s";
      card.style.boxShadow = "0 0 0 2px var(--accent)";
      setTimeout(() => { card.style.boxShadow = ""; }, 1200);
    });
  });
}

// ------------------------------------------------------------------ start

// Primo render immediato: senza sessione mostra il login (poi /auth/me
// può confermare la sessione già attiva nel cookie e re-renderizzare).
render();

(async function init() {
  try {
    const me = await fetchJSON("/auth/me");
    setUser(me);
  } catch (_) {
    // 401 → l'interceptor ha già mostrato la vista di login;
    // server irraggiungibile → la vista di login resta visibile e il
    // submit fallirà con l'errore di rete nel messaggio.
    return;
  }
  render();
})();

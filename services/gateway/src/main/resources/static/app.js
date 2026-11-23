"use strict";

// The token lives only in memory: it disappears when the tab is closed or reloaded.
// Every value coming from the server is written with textContent, never innerHTML (no XSS).
const state = { token: null, claims: null, timer: null };
const $ = (id) => document.getElementById(id);

const MESSAGES = {
  400: "Requête refusée : contenu invalide ou suspect.",
  401: "Identifiants invalides ou session expirée.",
  403: "Vous n'avez pas le droit d'effectuer cette action.",
  413: "Document trop volumineux.",
  422: "Certains champs sont invalides.",
  429: "Trop de tentatives. Réessayez dans une minute.",
  502: "Service indisponible. Réessayez dans un instant.",
};

function decodeClaims(token) {
  // Display only: the signature is verified by the gateway and by every service, not here.
  const part = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
  const json = decodeURIComponent(Array.from(atob(part), (c) => "%" + c.charCodeAt(0).toString(16).padStart(2, "0")).join(""));
  return JSON.parse(json);
}

function show(el, text, kind) {
  el.textContent = text || "";
  el.className = "msg" + (text ? " " + kind : "");
}

async function api(path, { method = "GET", body } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (state.token) headers.Authorization = "Bearer " + state.token;
  let res;
  try {
    res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  } catch {
    throw { status: 0, message: "Le serveur ne répond pas." };
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401 && state.token) {
      logout("Votre session a expiré. Reconnectez-vous.");
    }
    const detail = typeof data.detail === "string" ? data.detail : "";
    throw { status: res.status, message: (MESSAGES[res.status] || "Erreur " + res.status + ".") + (detail ? " (" + detail + ")" : "") };
  }
  return data;
}

function busy(button, on) {
  button.disabled = on;
}

/* ---------------------------------------------------------------- session */

function login(token) {
  state.token = token;
  state.claims = decodeClaims(token);
  const roles = state.claims.roles || [];
  $("who").textContent = state.claims.sub;
  const tags = $("roles");
  tags.replaceChildren(...roles.concat((state.claims.groups || []).map((g) => "groupe " + g)).map((r) => {
    const s = document.createElement("span");
    s.className = "tag";
    s.textContent = r;
    return s;
  }));
  $("tab-ask").hidden = !roles.includes("QUERY");
  $("tab-upload").hidden = !roles.includes("INGEST");
  renderGroups(state.claims.groups || []);
  $("login-view").hidden = true;
  $("session").hidden = false;
  $("app-view").hidden = false;
  const first = document.querySelector(".tab:not([hidden])");
  if (first) select(first.dataset.tab);
  tick();
  state.timer = setInterval(tick, 15000);
}

function logout(message) {
  state.token = null;
  state.claims = null;
  clearInterval(state.timer);
  $("session").hidden = true;
  $("app-view").hidden = true;
  $("login-view").hidden = false;
  $("password").value = "";
  $("answer").hidden = true;
  show($("login-msg"), message || "", "error");
  $("username").focus();
}

function tick() {
  if (!state.claims) return;
  const left = Math.round((state.claims.exp * 1000 - Date.now()) / 60000);
  if (left <= 0) return logout("Votre session a expiré. Reconnectez-vous.");
  $("expiry").textContent = "session : " + left + " min";
}

$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const button = $("login-btn");
  const username = $("username").value.trim();
  const password = $("password").value;
  if (!username || !password) return show($("login-msg"), "Saisissez votre identifiant et votre mot de passe.", "error");
  busy(button, true);
  show($("login-msg"), "");
  try {
    const data = await api("/api/auth/login", { method: "POST", body: { username, password } });
    login(data.access_token);
  } catch (err) {
    show($("login-msg"), err.message, "error");
  } finally {
    busy(button, false);
  }
});

$("logout").addEventListener("click", () => logout());

/* ---------------------------------------------------------------- tabs */

function select(name) {
  document.querySelectorAll(".tab").forEach((t) => t.setAttribute("aria-selected", String(t.dataset.tab === name)));
  ["ask", "upload"].forEach((p) => { $("panel-" + p).hidden = p !== name; });
}
document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => select(t.dataset.tab)));

/* ---------------------------------------------------------------- ask */

$("question").addEventListener("input", (e) => { $("question-count").textContent = e.target.value.length + " / 1000"; });

$("ask-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const question = $("question").value.trim();
  if (question.length < 3) return show($("ask-msg"), "La question doit faire au moins 3 caractères.", "error");
  const button = $("ask-btn");
  busy(button, true);
  show($("ask-msg"), "");
  try {
    const data = await api("/api/query", { method: "POST", body: { question } });
    $("answer-text").textContent = data.answer;
    const list = $("sources");
    const items = (data.sources || []).map((s) => {
      const li = document.createElement("li");
      const title = document.createElement("span");
      title.textContent = s.title;
      const score = document.createElement("span");
      score.className = "score";
      score.textContent = Number(s.score).toFixed(2);
      li.append(title, score);
      return li;
    });
    if (!items.length) {
      const li = document.createElement("li");
      li.className = "none";
      li.textContent = "Aucun document de vos groupes ne correspond.";
      items.push(li);
    }
    list.replaceChildren(...items);
    $("answer").hidden = false;
  } catch (err) {
    $("answer").hidden = true;
    show($("ask-msg"), err.message, "error");
  } finally {
    busy(button, false);
  }
});

/* ---------------------------------------------------------------- upload */

function renderGroups(groups) {
  const box = $("group-list");
  if (!groups.length) {
    const p = document.createElement("p");
    p.className = "hint";
    p.textContent = "Vous n'appartenez à aucun groupe.";
    return box.replaceChildren(p);
  }
  box.replaceChildren(...groups.map((g, i) => {
    const label = document.createElement("label");
    label.className = "check";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.value = g;
    input.id = "group-" + i;
    input.checked = i === 0;
    label.append(input, document.createTextNode(g));
    return label;
  }));
}

$("text").addEventListener("input", (e) => {
  $("text-count").textContent = e.target.value.length.toLocaleString("fr-FR") + " / 200 000";
});

$("upload-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const title = $("title").value.trim();
  const text = $("text").value;
  const allowed_groups = Array.from(document.querySelectorAll("#group-list input:checked"), (i) => i.value);
  if (!title || !text.trim()) return show($("upload-msg"), "Le titre et le contenu sont obligatoires.", "error");
  if (!allowed_groups.length) return show($("upload-msg"), "Choisissez au moins un groupe.", "error");
  const button = $("upload-btn");
  busy(button, true);
  show($("upload-msg"), "");
  try {
    const data = await api("/api/documents", { method: "POST", body: { title, text, allowed_groups } });
    const masked = data.redactions ? ", " + data.redactions + " élément(s) sensible(s) masqué(s)" : "";
    show($("upload-msg"), "Document déposé : " + data.chunks + " passage(s) indexé(s)" + masked + ".", "ok");
    $("upload-form").reset();
    renderGroups(state.claims.groups || []);
    $("text-count").textContent = "0 / 200 000";
  } catch (err) {
    show($("upload-msg"), err.message, "error");
  } finally {
    busy(button, false);
  }
});

"use strict";
const $ = (id) => document.getElementById(id);
const fragment = new URLSearchParams(location.hash.slice(1));
const provided = fragment.get("access");
if (provided) {
  sessionStorage.setItem("chio_workbench_access", provided);
  history.replaceState(null, "", location.pathname);
}
const token = sessionStorage.getItem("chio_workbench_access");
let selected = null;
let loading = false;
let stopping = false;
let lastBody = "";
const escape = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const label = (value) => String(value).replaceAll("_", " ");
async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  });
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      message = (await response.json()).error || message;
    } catch {}
    if (response.status === 401)
      message = "Access expired. Open the new access URL from your terminal.";
    throw new Error(message);
  }
  return response.status === 202 && path.endsWith("/stop")
    ? null
    : response.json();
}
function showError(error) {
  $("error").hidden = false;
  $("error").textContent = error.message;
}
function select(id) {
  selected = id;
  lastBody = "";
  stopping = false;
  $("compose").hidden = Boolean(id);
  $("run").hidden = !id;
  $("error").hidden = true;
  if (id) {
    $("run-title").textContent = "Loading task…";
    $("tasks").replaceChildren();
    $("metrics").replaceChildren();
    $("stop").hidden = true;
  }
  refresh();
}
function render(run) {
  const body = JSON.stringify(run);
  if (body === lastBody) return;
  lastBody = body;
  $("run-title").textContent = run.prompt;
  $("run-status").innerHTML =
    `<span class="badge ${escape(run.status)}">${escape(label(run.status))}</span>${run.error ? `<span class="run-error">${escape(run.error)}</span>` : ""}`;
  $("stop").hidden = !["running", "stopping"].includes(run.status);
  $("stop").disabled = stopping;
  $("stop").textContent = stopping ? "Stopping…" : "Stop task";
  const actions = run.tasks.flatMap((task) => task.actions);
  const input = run.tasks.reduce((sum, task) => sum + task.input_tokens, 0);
  const output = run.tasks.reduce((sum, task) => sum + task.output_tokens, 0);
  $("metrics").innerHTML =
    `<div><strong>${actions.length}<small> / ${run.call_limit}</small></strong><span>tool calls used</span></div><div><strong>${input.toLocaleString()}</strong><span>input tokens reported</span></div><div><strong>${output.toLocaleString()}</strong><span>output tokens reported</span></div><div><strong>${actions.filter((a) => a.receipt).length}</strong><span>signed receipts</span></div>`;
  const open = new Set(
    [...document.querySelectorAll("details[open]")].map((el) => el.dataset.key),
  );
  $("tasks").innerHTML = run.tasks
    .map(
      (task, index) =>
        `<article class="task"><div class="task-head"><span class="number">0${index + 1}</span><h2>${escape(label(task.role))}</h2><span class="badge ${escape(task.status)}">${escape(label(task.status))}</span><span class="allowance">${task.actions.length} / ${task.call_limit} calls</span></div><div class="authority">${task.capability.scope.grants.map((g) => `<code>${escape(g.tool_name)}</code>`).join("")}<details data-key="cap-${index}" ${open.has(`cap-${index}`) ? "open" : ""}><summary>Delegated authority</summary><pre>${escape(JSON.stringify(task.capability, null, 2))}</pre></details></div>${task.actions.map((action) => `<details class="action" data-key="${escape(action.id)}" ${open.has(action.id) ? "open" : ""}><summary><span class="dot ${escape(action.state)}"></span><code>${escape(action.tool)}</code><span>${escape(action.arguments.path || "")}</span><span class="action-state">${escape(action.state)}</span></summary><div class="action-detail"><h3>Arguments</h3><pre>${escape(JSON.stringify(action.arguments, null, 2))}</pre><h3>Result</h3><pre>${escape(JSON.stringify(action.output || action.error || "Awaiting result", null, 2))}</pre>${action.receipt ? `<h3>Signed kernel receipt</h3><pre>${escape(JSON.stringify(action.receipt, null, 2))}</pre>` : ""}</div></details>`).join("")}${task.summary ? `<div class="summary">${escape(task.summary)}</div>` : ""}</article>`,
    )
    .join("");
}
async function refresh() {
  if (loading || !token) return;
  loading = true;
  try {
    const runs = await api("/api/runs");
    $("runs").replaceChildren(
      ...runs.map((run) => {
        const button = document.createElement("button");
        button.className = `run-link ${run.id === selected ? "selected" : ""}`;
        button.innerHTML = `<span>${escape(run.prompt)}</span><small>${escape(label(run.status))}</small>`;
        button.addEventListener("click", () => select(run.id));
        return button;
      }),
    );
    const id = selected;
    if (id) {
      const run = await api(`/api/runs/${id}`);
      if (selected === id) render(run);
    }
  } catch (error) {
    showError(error);
  } finally {
    loading = false;
  }
}
$("task-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("start").disabled = true;
  $("error").hidden = true;
  try {
    const run = await api("/api/runs", {
      method: "POST",
      body: JSON.stringify({
        prompt: $("prompt").value,
        call_limit: Number($("allowance").value),
      }),
    });
    select(run.id);
  } catch (error) {
    showError(error);
  } finally {
    $("start").disabled = false;
  }
});
$("stop").addEventListener("click", async () => {
  const id = selected;
  stopping = true;
  $("stop").disabled = true;
  $("stop").textContent = "Stopping…";
  try {
    await api(`/api/runs/${id}/stop`, { method: "POST" });
  } catch (error) {
    stopping = false;
    $("stop").disabled = false;
    showError(error);
  }
  refresh();
});
$("new-task").addEventListener("click", () => select(null));
async function boot() {
  if (!token) {
    $("access").hidden = false;
    return;
  }
  $("app").hidden = false;
  try {
    const config = await api("/api/config");
    $("workspace").textContent = config.workspace;
    $("model").textContent = config.model;
    await refresh();
  } catch (error) {
    showError(error);
  }
  setInterval(refresh, 1500);
}
boot();

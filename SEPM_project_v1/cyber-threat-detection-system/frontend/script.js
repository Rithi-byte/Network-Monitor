(function () {
  const API = "";

  async function api(path, opts) {
    const r = await fetch(API + path, {
      credentials: "include",
      headers: { "Content-Type": "application/json", ...(opts && opts.headers) },
      ...opts,
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.message || data.error || r.statusText);
    return data;
  }

  const page = document.body.dataset.page;

  /* -------- Landing (home) -------- */
  if (page === "home") {
    fetch(API + "/api/session", { credentials: "include" })
      .then((r) => r.json())
      .then((s) => {
        const dash = document.getElementById("navDashboard");
        const sim = document.getElementById("navSimulator");
        const guest = document.getElementById("guestNav");
        const user = document.getElementById("userNav");
        const adm = document.getElementById("navAdmin");
        if (s.authenticated) {
          if (dash) dash.hidden = false;
          if (sim) sim.hidden = false;
          if (guest) guest.hidden = true;
          if (user) user.hidden = false;
          if (adm) adm.hidden = s.role !== "admin";
        } else {
          if (dash) dash.hidden = true;
          if (sim) sim.hidden = true;
          if (adm) adm.hidden = true;
          if (guest) guest.hidden = false;
          if (user) user.hidden = true;
        }
      })
      .catch(() => {});
    return;
  }

  /* -------- Login -------- */
  if (page === "login") {
    const params = new URLSearchParams(window.location.search);
    if (params.get("registered") === "1") {
      const ban = document.getElementById("registeredBanner");
      if (ban) ban.hidden = false;
    }
    document.getElementById("loginForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const err = document.getElementById("loginError");
      err.hidden = true;
      try {
        await api("/api/login", {
          method: "POST",
          body: JSON.stringify({
            username: document.getElementById("username").value,
            password: document.getElementById("password").value,
          }),
        });
        window.location.href = "/dashboard";
      } catch (x) {
        err.textContent = x.message || "Login failed";
        err.hidden = false;
      }
    });
    return;
  }

  /* -------- Register -------- */
  if (page === "register") {
    document.getElementById("regForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const err = document.getElementById("regError");
      const ok = document.getElementById("regOk");
      err.hidden = true;
      ok.hidden = true;
      try {
        await api("/api/register", {
          method: "POST",
          body: JSON.stringify({
            username: document.getElementById("reg_user").value,
            password: document.getElementById("reg_pass").value,
          }),
        });
        window.location.href = "/login?registered=1";
      } catch (x) {
        err.textContent = x.message || "Registration failed";
        err.hidden = false;
      }
    });
    return;
  }

  /* -------- Auth gate -------- */
  async function requireAuth() {
    const s = await fetch(API + "/api/session", { credentials: "include" }).then((r) => r.json());
    if (!s.authenticated) {
      window.location.href = "/login";
      return null;
    }
    return s;
  }

  /* -------- Dashboard -------- */
  let charts = { time: null, dist: null, vol: null };

  function destroyCharts() {
    Object.values(charts).forEach((c) => c && c.destroy());
    charts = { time: null, dist: null, vol: null };
  }

  function badgeClass(risk) {
    const r = (risk || "").toLowerCase();
    if (r.includes("critical") || r.includes("high")) return "badge-bad";
    if (r.includes("medium")) return "badge-warn";
    return "badge-ok";
  }

  async function refreshTables() {
    const logs = await api("/api/logs");
    const alerts = await api("/api/alerts");
    document.getElementById("logCount").textContent = String(logs.logs.length);
    document.getElementById("alertCount").textContent = String(alerts.alerts.length);

    const lb = document.getElementById("logsBody");
    lb.innerHTML = "";
    [...logs.logs].reverse().slice(0, 80).forEach((row) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${escapeHtml((row.time || "").slice(0, 19))}</td>
        <td>${escapeHtml(row.src_ip)}</td>
        <td>${escapeHtml(row.dst_ip)}</td>
        <td>${escapeHtml(row.protocol)}</td>
        <td>${escapeHtml(row.packets)}</td>
        <td>${escapeHtml(row.attack_type)}</td>`;
      lb.appendChild(tr);
    });

    const ab = document.getElementById("alertsBody");
    ab.innerHTML = "";
    alerts.alerts.slice(0, 80).forEach((a) => {
      const tr = document.createElement("tr");
      const b = badgeClass(a.risk_level);
      tr.innerHTML = `<td>${escapeHtml((a.timestamp || "").slice(0, 19))}</td>
        <td>${escapeHtml(a.attack_type)}</td>
        <td>${escapeHtml(a.source_ip)}</td>
        <td>${escapeHtml(a.destination_ip)}</td>
        <td><span class="badge ${b}">${escapeHtml(a.risk_level)}</span></td>`;
      ab.appendChild(tr);
    });

    const stats = await api("/api/chart-stats");
    destroyCharts();
    const lblT = Object.keys(stats.attacks_over_time);
    const dataT = lblT.map((k) => stats.attacks_over_time[k]);
    const ctxT = document.getElementById("chartTime");
    if (ctxT) {
      charts.time = new Chart(ctxT, {
        type: "line",
        data: {
          labels: lblT,
          datasets: [
            {
              label: "Alerts (count by time key)",
              data: dataT,
              borderColor: "#3b82f6",
              tension: 0.2,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { labels: { color: "#94a3b8" } } },
          scales: {
            x: { ticks: { color: "#94a3b8", maxRotation: 45 } },
            y: { ticks: { color: "#94a3b8" } },
          },
        },
      });
    }

    const dist = stats.attack_distribution;
    const ctxD = document.getElementById("chartDist");
    if (ctxD && dist && Object.keys(dist).length) {
      charts.dist = new Chart(ctxD, {
        type: "doughnut",
        data: {
          labels: Object.keys(dist),
          datasets: [
            {
              data: Object.values(dist),
              backgroundColor: ["#22c55e", "#ef4444", "#f59e0b", "#3b82f6", "#a855f7", "#64748b"],
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { labels: { color: "#94a3b8" } } },
        },
      });
    } else if (ctxD) {
      const simDist = {};
      logs.logs.forEach((row) => {
        const k = row.attack_type || "?";
        simDist[k] = (simDist[k] || 0) + 1;
      });
      charts.dist = new Chart(ctxD, {
        type: "bar",
        data: {
          labels: Object.keys(simDist),
          datasets: [
            {
              label: "Scenarios in logs",
              data: Object.values(simDist),
              backgroundColor: "#3b82f6aa",
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { labels: { color: "#94a3b8" } } },
          scales: {
            x: { ticks: { color: "#94a3b8" } },
            y: { ticks: { color: "#94a3b8" } },
          },
        },
      });
    }

    const lblV = Object.keys(stats.traffic_volume);
    const dataV = lblV.map((k) => stats.traffic_volume[k]);
    const ctxV = document.getElementById("chartVol");
    if (ctxV) {
      charts.vol = new Chart(ctxV, {
        type: "bar",
        data: {
          labels: lblV,
          datasets: [
            {
              label: "Packet volume by time (hour)",
              data: dataV,
              backgroundColor: "#22c55e88",
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { labels: { color: "#94a3b8" } } },
          scales: {
            x: { ticks: { color: "#94a3b8", maxRotation: 60 } },
            y: { ticks: { color: "#94a3b8" } },
          },
        },
      });
    }
  }

  function escapeHtml(s) {
    const d = document.createElement("div");
    d.textContent = s == null ? "" : String(s);
    return d.innerHTML;
  }

  function buildReasonHtml(reason, opts) {
    opts = opts || {};
    if (!reason) {
      return '<div class="reason-panel-inner"><p class="muted">No structured explanation returned.</p></div>';
    }
    const randomTag =
      opts.random === true
        ? '<span class="reason-tag">Random packet draw</span>'
        : "";
    let html = '<div class="reason-panel-inner">';
    html +=
      '<div class="reason-panel-title-row"><strong class="reason-title">Reason for this detection</strong>' +
      randomTag +
      "</div>";
    html += '<p class="reason-intro">' + escapeHtml(reason.intro || "") + "</p>";
    if (reason.has_factors && reason.factors && reason.factors.length) {
      html += '<ol class="reason-steps">';
      for (let i = 0; i < reason.factors.length; i++) {
        const fac = reason.factors[i];
        html +=
          '<li><span class="reason-step-name">' +
          escapeHtml(fac.name) +
          '</span> <span class="reason-impact">impact <code>' +
          escapeHtml(String(fac.impact)) +
          '</code></span><div class="reason-step-role">' +
          escapeHtml(fac.role) +
          "</div></li>";
      }
      html += "</ol>";
    } else {
      html += '<p class="muted reason-none">No ranked factors returned.</p>';
    }
    if (reason.basis_label) {
      html +=
        '<p class="reason-basis muted"><span class="reason-basis-label">Basis:</span> ' +
        escapeHtml(reason.basis_label) +
        "</p>";
    }
    if (reason.method) {
      html +=
        '<p class="reason-method muted"><span class="reason-basis-label">Method:</span> ' +
        escapeHtml(reason.method) +
        "</p>";
    }
    html += "</div>";
    return html;
  }

  if (page === "dashboard") {
    requireAuth().then((s) => {
      if (!s) return;
      document.getElementById("whoami").textContent = s.username + " (" + s.role + ")";
      const na = document.getElementById("navAdmin");
      if (na) na.hidden = s.role !== "admin";
    });

    document.getElementById("logoutBtn").addEventListener("click", async () => {
      await api("/api/logout", { method: "POST" });
      window.location.href = "/login";
    });

    const qRand = document.getElementById("q_random");
    const qManual = document.getElementById("quickManualFields");
    function syncQuickManual() {
      if (!qManual) return;
      if (qRand && qRand.checked) qManual.classList.add("form-disabled");
      else qManual.classList.remove("form-disabled");
    }
    if (qRand) {
      qRand.addEventListener("change", syncQuickManual);
      syncQuickManual();
    }

    document.getElementById("quickForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const box = document.getElementById("quickResult");
      const sum = document.getElementById("mlSummary");
      const reasonPanel = document.getElementById("reasonPanel");
      const exSub = document.getElementById("explainSub");
      const ex = document.getElementById("explainList");
      box.hidden = true;
      if (reasonPanel) {
        reasonPanel.innerHTML = "";
        reasonPanel.hidden = true;
      }
      try {
        const useRandom = !!(qRand && qRand.checked);
        const payload = {
          random: useRandom,
          source_device: document.getElementById("q_src").value,
          destination_device: document.getElementById("q_dst").value,
          protocol: document.getElementById("q_proto").value,
          attack_type: document.getElementById("q_attack").value,
          num_packets: document.getElementById("q_pkts").value,
        };
        const res = await api("/api/quick-simulation", {
          method: "POST",
          body: JSON.stringify(payload),
        });
        if (res.error) {
          box.textContent = res.error;
          box.hidden = false;
          return;
        }
        const p = res.prediction;
        const lbl = p ? p.label : "—";
        const conf = p ? (p.confidence * 100).toFixed(1) : "—";
        const detP = res.detection_packet_count != null ? res.detection_packet_count : res.log.packets;
        const detProto = res.detection_protocol != null ? res.detection_protocol : res.log.protocol;
        const truth = res.log.attack_type;
        const agree = p && p.label === truth;
        const summaryBlock = `<div class="quick-summary"><strong>Prediction:</strong> ${escapeHtml(lbl)} (${conf}% confidence)<br/>
          <strong>Generated log class:</strong> ${escapeHtml(truth)} (logged ${escapeHtml(res.log.packets)} pkts) ${res.randomized ? "· <em>random draw</em>" : ""}<br/>
          <strong>Match:</strong> ${agree ? "detector agrees with generator" : "detector differs — see reason below"}<br/>
          <strong>ML feature vector:</strong> ${escapeHtml(detP)} pkts, ${escapeHtml(detProto)}<br/>
          <strong>Alert:</strong> ${res.alert_created ? "created" : "none (normal)"}</div>`;
        const reasonBlock =
          p && res.explanation_reason
            ? `<div class="reason-in-quick reason-panel">${buildReasonHtml(res.explanation_reason, {
                random: res.randomized,
              })}</div>`
            : res.explanation_narrative
              ? `<div class="reason-in-quick reason-panel"><div class="reason-panel-inner"><div class="reason-panel-title-row"><strong class="reason-title">Reason for this detection</strong>${
                  res.randomized ? '<span class="reason-tag">Random packet draw</span>' : ""
                }</div><p class="reason-intro">${escapeHtml(
                  res.explanation_narrative
                )}</p></div></div>`
              : "";
        box.innerHTML = summaryBlock + reasonBlock;
        box.hidden = false;
        if (p) {
          sum.textContent = `Model: ${lbl} — confidence ${conf}% — risk ${res.risk_level || ""}`;
        }
        if (reasonPanel && p && (res.explanation_reason || res.explanation_narrative)) {
          if (res.explanation_reason) {
            reasonPanel.innerHTML = buildReasonHtml(res.explanation_reason, { random: res.randomized });
          } else {
            reasonPanel.innerHTML =
              '<div class="reason-panel-inner"><p class="reason-intro">' +
              escapeHtml(res.explanation_narrative) +
              "</p></div>";
          }
          reasonPanel.hidden = false;
        }
        ex.innerHTML = "";
        if (res.explanation && res.explanation.top_features && res.explanation.top_features.length) {
          if (exSub) exSub.hidden = false;
          res.explanation.top_features.forEach((f) => {
            const li = document.createElement("li");
            li.textContent = `${f.feature}: impact ${f.impact}`;
            ex.appendChild(li);
          });
          ex.hidden = false;
        } else {
          if (exSub) exSub.hidden = true;
          ex.hidden = true;
        }
        await refreshTables();
      } catch (x) {
        box.textContent = x.message || "Failed";
        box.hidden = false;
      }
    });

    refreshTables().catch(() => {});
    return;
  }

  /* -------- Simulator (jsPlumb) -------- */
  if (page === "simulator") {
    requireAuth().then((s) => {
      if (!s) return;
      const na = document.getElementById("navAdmin");
      if (na) na.hidden = s.role !== "admin";
    });

    document.getElementById("logoutBtnSim").addEventListener("click", async () => {
      await api("/api/logout", { method: "POST" });
      window.location.href = "/login";
    });

    const canvas = document.getElementById("simCanvas");
    let jInstance = null;
    let devCounter = 0;
    const devices = new Map();
    const links = [];

    function syncLinkTable() {
      const tb = document.getElementById("linkTable");
      tb.innerHTML = "";
      links.forEach((L, idx) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `<td>${escapeHtml(L.src)}</td><td>${escapeHtml(L.tgt)}</td><td></td>`;
        const sel = document.createElement("select");
        ["Normal", "DoS", "Port Scan", "Brute Force"].forEach((a) => {
          const o = document.createElement("option");
          o.value = a;
          o.textContent = a;
          if (a === L.attack) o.selected = true;
          sel.appendChild(o);
        });
        sel.addEventListener("change", () => {
          links[idx].attack = sel.value;
        });
        tr.children[2].appendChild(sel);
        tb.appendChild(tr);
      });
    }

    function addDevice(kind) {
      devCounter++;
      const id = "d" + devCounter;
      const el = document.createElement("div");
      el.className = "device";
      el.id = id;
      el.style.left = 40 + Math.random() * 180 + "px";
      el.style.top = 40 + Math.random() * 200 + "px";
      el.dataset.deviceType = kind;
      const ipDefault =
        kind === "Laptop"
          ? "10.0.1." + (50 + devCounter)
          : kind === "Router"
            ? "10.0.0.1"
            : "10.0.2." + (50 + devCounter);
      el.innerHTML = `<h4>${kind}</h4>
        <label style="font-size:0.65rem;color:var(--muted)">IP</label>
        <input class="ip-field" type="text" value="${ipDefault}" />`;
      canvas.appendChild(el);
      devices.set(id, { kind, el });

      jInstance.draggable(el, { containment: canvas });

      const epIn = jInstance.addEndpoint(el, {
        anchor: "Left",
        endpoint: ["Dot", { radius: 6 }],
        paintStyle: { fill: "#22c55e" },
        isSource: true,
        isTarget: true,
        maxConnections: -1,
      });
      const epOut = jInstance.addEndpoint(el, {
        anchor: "Right",
        endpoint: ["Dot", { radius: 6 }],
        paintStyle: { fill: "#3b82f6" },
        isSource: true,
        isTarget: true,
        maxConnections: -1,
      });
      el._epIn = epIn;
      el._epOut = epOut;
    }

    jsPlumb.ready(function () {
      jInstance = jsPlumb.getInstance({
        Container: canvas,
        Connector: ["Bezier", { curviness: 60 }],
        PaintStyle: { stroke: "#64748b", strokeWidth: 2 },
        EndpointStyle: { radius: 5 },
        HoverPaintStyle: { stroke: "#3b82f6", strokeWidth: 3 },
        ConnectionOverlays: [
          ["Arrow", { location: 1, width: 10, length: 10, foldback: 0.8 }],
        ],
      });

      jInstance.bind("connection", function (info) {
        const src = info.connection.sourceId;
        const tgt = info.connection.targetId;
        if (src === tgt) return;
        const id = src + "->" + tgt;
        if (links.some((L) => L.key === id)) return;
        links.push({ key: id, src, tgt, attack: "Normal" });
        syncLinkTable();
      });

      jInstance.bind("connectionDetached", function (info) {
        const src = info.connection.sourceId;
        const tgt = info.connection.targetId;
        const id = src + "->" + tgt;
        const ix = links.findIndex((L) => L.key === id);
        if (ix >= 0) links.splice(ix, 1);
        syncLinkTable();
      });

      document.querySelectorAll("[data-add]").forEach((btn) => {
        btn.addEventListener("click", () => addDevice(btn.getAttribute("data-add")));
      });
    });

    const vRand = document.getElementById("v_random");
    const paletteEl = document.querySelector("#simCanvas")?.parentElement?.querySelector(".palette");
    function syncVisualRandomUi() {
      if (!paletteEl || !vRand) return;
      if (vRand.checked) {
        paletteEl.classList.add("form-disabled");
        document.getElementById("linkTable")?.closest(".table-wrap")?.classList.add("form-disabled");
      } else {
        paletteEl.classList.remove("form-disabled");
        document.getElementById("linkTable")?.closest(".table-wrap")?.classList.remove("form-disabled");
      }
    }
    if (vRand) vRand.addEventListener("change", syncVisualRandomUi);

    document.getElementById("runVisual").addEventListener("click", async () => {
      const out = document.getElementById("visualOut");
      out.innerHTML = "<p>Running…</p>";
      syncVisualRandomUi();
      const useRandom = !!(vRand && vRand.checked);
      const proto = document.getElementById("v_proto").value;
      const pkts = parseInt(document.getElementById("v_pkts").value || "200", 10);
      const flows = [];
      for (const L of links) {
        const se = devices.get(L.src);
        const te = devices.get(L.tgt);
        if (!se || !te) continue;
        const sip = se.el.querySelector(".ip-field").value.trim();
        const dip = te.el.querySelector(".ip-field").value.trim();
        flows.push({
          source_device: se.kind,
          destination_device: te.kind,
          protocol: proto,
          attack_type: L.attack,
          num_packets: pkts,
          src_ip: sip,
          dst_ip: dip,
        });
      }
      if (!flows.length) {
        out.innerHTML = "<p>Add devices and connect them first.</p>";
        return;
      }
      try {
        const res = await api("/api/visual-simulation", {
          method: "POST",
          body: JSON.stringify({ flows, random: useRandom }),
        });
        const blocks = res.results.map((r, i) => {
          const p = r.prediction;
          const rndTag = r.randomized
            ? ' · <span class="reason-tag">Random packet draw</span>'
            : "";
          const head =
            '<div class="visual-run-block"><div class="visual-run"><strong>#' +
            (i + 1) +
            "</strong> " +
            escapeHtml(r.log.src_ip) +
            "→" +
            escapeHtml(r.log.dst_ip) +
            " · generated: <code>" +
            escapeHtml(r.log.attack_type) +
            "</code> · model: <strong>" +
            escapeHtml(p ? p.label : "?") +
            "</strong> (" +
            (p ? (p.confidence * 100).toFixed(1) : "?") +
            "%) · alert: " +
            (r.alert_created ? "yes" : "no") +
            rndTag +
            "</div>";
          const reasonHtml = r.explanation_reason
            ? '<div class="reason-panel" style="margin-top:0.6rem">' +
              buildReasonHtml(r.explanation_reason, { random: r.randomized }) +
              "</div>"
            : r.explanation_narrative
              ? '<div class="reason-panel" style="margin-top:0.6rem"><div class="reason-panel-inner"><div class="reason-panel-title-row"><strong class="reason-title">Reason for this detection</strong>' +
                (r.randomized ? '<span class="reason-tag">Random packet draw</span>' : "") +
                '</div><p class="reason-intro">' +
                escapeHtml(r.explanation_narrative) +
                "</p></div></div>"
              : "";
          return head + reasonHtml + "</div>";
        });
        out.innerHTML = blocks.join('<hr class="visual-sep"/>');
      } catch (e) {
        out.innerHTML = "<p>" + escapeHtml(e.message || String(e)) + "</p>";
      }
    });

    return;
  }

  /* -------- Admin (database + users) -------- */
  if (page === "admin") {
    (async function () {
      const s = await requireAuth();
      if (!s) return;
      if (s.role !== "admin") {
        window.location.href = "/dashboard";
        return;
      }
      const who = document.getElementById("whoamiAdmin");
      if (who) who.textContent = s.username + " (admin)";
      document.getElementById("logoutBtnAdmin").addEventListener("click", async () => {
        await api("/api/logout", { method: "POST" });
        window.location.href = "/login";
      });

      function setTab(name) {
        document.querySelectorAll(".tab-btn").forEach((b) => {
          const on = b.getAttribute("data-tab") === name;
          b.classList.toggle("active", on);
          b.setAttribute("aria-selected", on ? "true" : "false");
        });
        document.querySelectorAll(".admin-panel").forEach((p) => {
          p.hidden = p.getAttribute("data-panel") !== name;
        });
      }
      document.querySelectorAll(".tab-btn").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const name = btn.getAttribute("data-tab");
          setTab(name);
          if (name === "logs") await refreshLogs();
          if (name === "alerts") await refreshAlerts();
        });
      });

      async function refreshUsers() {
        const res = await api("/api/admin/users");
        const tb = document.getElementById("adminUsersBody");
        tb.innerHTML = "";
        res.users.forEach((u) => {
          const tr = document.createElement("tr");
          const td1 = document.createElement("td");
          td1.textContent = u.username;
          const td2 = document.createElement("td");
          const sel = document.createElement("select");
          sel.className = "admin-role-select";
          ["user", "admin"].forEach((r) => {
            const o = document.createElement("option");
            o.value = r;
            o.textContent = r;
            if (r === u.role) o.selected = true;
            sel.appendChild(o);
          });
          sel.addEventListener("change", async () => {
            try {
              await api("/api/admin/users/" + encodeURIComponent(u.username), {
                method: "PATCH",
                body: JSON.stringify({ role: sel.value }),
              });
              await refreshUsers();
            } catch (e) {
              alert(e.message);
              await refreshUsers();
            }
          });
          td2.appendChild(sel);
          const td3 = document.createElement("td");
          const del = document.createElement("button");
          del.type = "button";
          del.className = "btn btn-danger btn-sm";
          del.textContent = "Delete";
          del.addEventListener("click", async () => {
            if (!confirm("Delete user \"" + u.username + "\"?")) return;
            try {
              await api("/api/admin/users/" + encodeURIComponent(u.username), {
                method: "DELETE",
              });
              await refreshUsers();
            } catch (e) {
              alert(e.message);
            }
          });
          td3.appendChild(del);
          tr.appendChild(td1);
          tr.appendChild(td2);
          tr.appendChild(td3);
          tb.appendChild(tr);
        });
      }

      async function refreshLogs() {
        const res = await api("/api/admin/database/logs?limit=800");
        const tb = document.getElementById("adminLogsBody");
        tb.innerHTML = "";
        [...res.logs].reverse().forEach((row) => {
          const tr = document.createElement("tr");
          tr.innerHTML = `<td>${escapeHtml((row.time || "").slice(0, 22))}</td>
            <td>${escapeHtml(row.src_ip)}</td>
            <td>${escapeHtml(row.dst_ip)}</td>
            <td>${escapeHtml(row.protocol)}</td>
            <td>${escapeHtml(row.packets)}</td>
            <td>${escapeHtml(row.attack_type)}</td>`;
          tb.appendChild(tr);
        });
      }

      async function refreshAlerts() {
        const res = await api("/api/admin/database/alerts?limit=800");
        const tb = document.getElementById("adminAlertsBody");
        tb.innerHTML = "";
        res.alerts.forEach((a) => {
          const tr = document.createElement("tr");
          tr.innerHTML = `<td>${escapeHtml((a.timestamp || "").slice(0, 22))}</td>
            <td>${escapeHtml(a.attack_type)}</td>
            <td>${escapeHtml(a.source_ip)}</td>
            <td>${escapeHtml(a.destination_ip)}</td>
            <td>${escapeHtml(a.risk_level)}</td>
            <td>${escapeHtml(a.confidence)}</td>`;
          tb.appendChild(tr);
        });
      }

      document.getElementById("adminAddUser").addEventListener("submit", async (e) => {
        e.preventDefault();
        const msg = document.getElementById("adminUserMsg");
        msg.textContent = "";
        try {
          await api("/api/admin/users", {
            method: "POST",
            body: JSON.stringify({
              username: document.getElementById("newUser").value.trim(),
              password: document.getElementById("newPass").value,
              role: document.getElementById("newRole").value,
            }),
          });
          document.getElementById("newUser").value = "";
          document.getElementById("newPass").value = "";
          msg.textContent = "User added.";
          await refreshUsers();
        } catch (err) {
          msg.textContent = err.message || "Failed";
        }
      });

      await refreshUsers();
      await refreshLogs();
      await refreshAlerts();
    })();
    return;
  }
})();

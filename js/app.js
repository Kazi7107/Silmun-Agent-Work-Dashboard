(() => {
  "use strict";

  const DATA_URL = "data/tracker.enc.json";
  const KEY_URL = "data/private-key.enc.json";
  const STORE_PW = "silmun-board-pw";
  const STORE_VIEW = "silmun-board-view";
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Leads see what they own. Kazim oversees the team, so his view is
  // everything that isn't solely on the leads or on ServiceNow.
  const LEADS = ["furqan", "zeeshan", "leads"];
  const OUTSIDE = ["servicenow"];
  const VIEWS = [
    { id: "all", label: "Everyone", test: null },
    { id: "leads", label: "CEO", test: (o) => LEADS.some((m) => o.includes(m)) },
    {
      id: "kazim", label: "Kazim & team", test: (o) => {
        const people = o.split(/,|&| and /).map((s) => s.trim()).filter(Boolean);
        if (!people.length) return true;
        return people.some((p) => !LEADS.some((m) => p.includes(m)) && !OUTSIDE.some((m) => p === m));
      },
    },
  ];

  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const store = {
    get(k) { try { return localStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
    del(k) { try { localStorage.removeItem(k); } catch { /* ignore */ } },
  };

  const savedView = store.get(STORE_VIEW);
  const state = { data: null, view: ["all", "leads", "kazim"].includes(savedView) ? savedView : "all", filter: "open", area: "All" };

  /* ---------- Crypto ---------- */
  const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  // 1. The password unlocks the private key (PBKDF2 + AES-GCM).
  // 2. The private key + the data's one-time public key give the data key (ECDH + HKDF).
  // 3. The data key decrypts the data (AES-GCM).
  async function unlockPrivateKey(wrapped, password) {
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
    const kek = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: b64(wrapped.salt), iterations: wrapped.iter, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
    );
    let pkcs8;
    try {
      pkcs8 = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(wrapped.iv) }, kek, b64(wrapped.data));
    } catch { throw new Error("password"); }
    return crypto.subtle.importKey("pkcs8", pkcs8, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  }

  async function decrypt(payload, privateKey) {
    const epk = await crypto.subtle.importKey("raw", b64(payload.epk), { name: "ECDH", namedCurve: "P-256" }, false, []);
    const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: epk }, privateKey, 256);
    const hk = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: b64(payload.salt), info: new TextEncoder().encode("silmun-board-v2") },
      hk, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
    );
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(payload.iv) }, key, b64(payload.data));
    return JSON.parse(new TextDecoder().decode(plain));
  }

  async function fetchJSON(url) {
    let res;
    try { res = await fetch(`${url}?t=${Date.now()}`, { cache: "no-store" }); } catch { throw new Error("load"); }
    if (!res.ok) throw new Error("load");
    return res.json();
  }

  /* ---------- Dates ---------- */
  const today = (() => { const d = new Date(); d.setHours(0, 0, 0, 0); return d; })();
  const parse = (s) => { if (!s) return null; const [y, m, d] = s.split("-").map(Number); return new Date(y, m - 1, d); };
  const diff = (s) => { const d = parse(s); return d ? Math.round((d - today) / 86400000) : null; };
  const fmt = (s, opts = { weekday: "short", month: "short", day: "numeric" }) => {
    const d = parse(s); return d ? d.toLocaleDateString("en-US", opts) : "";
  };
  function rel(s) {
    const n = diff(s);
    if (n === null) return { text: "no date", cls: "" };
    if (n < -1) return { text: `${-n} days late`, cls: "late" };
    if (n === -1) return { text: "1 day late", cls: "late" };
    if (n === 0) return { text: "today", cls: "soon" };
    if (n === 1) return { text: "tomorrow", cls: "soon" };
    if (n <= 7) return { text: `in ${n} days`, cls: "soon" };
    return { text: `in ${n} days`, cls: "" };
  }

  /* ---------- Helpers ---------- */
  const isDone = (s) => (s || "").toLowerCase() === "done";
  const statusCls = (s) => {
    const v = (s || "").toLowerCase();
    if (v === "in progress") return "s-progress";
    if (v === "waiting") return "s-waiting";
    if (v === "blocked") return "s-blocked";
    if (v === "done") return "s-done";
    return "s-todo";
  };
  const mine = (owner) => {
    const v = VIEWS.find((x) => x.id === state.view);
    if (!v || !v.test) return true;
    return v.test((owner || "").toLowerCase());
  };
  const isLate = (t) => !isDone(t.status) && t.due && diff(t.due) < 0;
  const isWeek = (t) => !isDone(t.status) && t.due && diff(t.due) >= 0 && diff(t.due) <= 7;
  const isStuck = (t) => ["blocked", "waiting"].includes((t.status || "").toLowerCase());
  const byDue = (a, b) => (a.due || "9999").localeCompare(b.due || "9999");

  const FILTERS = {
    open: (t) => !isDone(t.status),
    late: isLate,
    week: isWeek,
    stuck: isStuck,
    done: (t) => isDone(t.status),
  };

  /* ---------- Render ---------- */
  function renderHero() {
    const { data } = state;
    const launch = data.launch || {};
    const n = diff(launch.date);
    const daysEl = $("#days");
    const target = n === null ? 0 : Math.max(n, 0);
    countUp(daysEl, target);
    $(".days-unit").textContent = target === 1 ? "day" : "days";
    $("#launch-date").textContent = launch.date ? `to launch · ${fmt(launch.date, { weekday: "long", month: "long", day: "numeric", year: "numeric" })}` : "Launch date not set";
    const flag = $("#launch-flag");
    flag.textContent = launch.proposed ? "proposed" : "confirmed";
    flag.classList.toggle("ok", !launch.proposed);

    const ms = data.milestones || [];
    const done = ms.filter((m) => isDone(m.status)).length;
    $("#progress-bar").style.width = ms.length ? `${(done / ms.length) * 100}%` : "0";
    $("#progress-label").textContent = `${done} of ${ms.length} milestones done`;

    const updated = new Date(data.updated);
    $("#updated").textContent = isNaN(updated) ? "" : `Updated ${updated.toLocaleString("en-US", { month: "short", day: "numeric", hour: "numeric", minute: "2-digit", timeZone: "America/Los_Angeles" })} PT`;
  }

  function renderViewAs() {
    const box = $("#viewas");
    box.innerHTML = VIEWS.map((v) => `<button class="chip" data-view="${v.id}" aria-pressed="${v.id === state.view}">${esc(v.label)}</button>`).join("");
  }

  function renderStats() {
    const tasks = state.data.tasks.filter((t) => mine(t.owner));
    const decisions = state.data.decisions.open.filter((d) => mine(d.who));
    const late = tasks.filter(isLate).length;
    $("#n-late").textContent = late;
    $("#n-week").textContent = tasks.filter(isWeek).length;
    $("#n-decide").textContent = decisions.length;
    $("#n-blocked").textContent = tasks.filter(isStuck).length;
    $('[data-jump="late"]').classList.toggle("hot", late > 0);
  }

  const isExec = () => state.view === "leads";
  const leadsOwn = (o) => LEADS.some((m) => (o || "").toLowerCase().includes(m));

  // What the leads need to act on: their open decisions plus any open task on them.
  function leadItems() {
    const decisions = state.data.decisions.open.filter((d) => leadsOwn(d.who));
    const tasks = state.data.tasks.filter((t) => leadsOwn(t.owner) && !isDone(t.status))
      .map((t) => ({ title: t.title, who: t.owner, date: t.due, notes: t.notes }));
    const seen = new Set(decisions.map((d) => d.title.toLowerCase()));
    return [...decisions, ...tasks.filter((t) => !seen.has(t.title.toLowerCase()))];
  }

  function renderDecisions() {
    $("#decide-h").innerHTML = isExec() ? 'What we need from <span class="hlw">you</span>' : 'Waiting on a <span class="hlw">decision</span>';
    const source = isExec() ? leadItems() : state.data.decisions.open.filter((d) => mine(d.who));
    const list = source.sort((a, b) => (a.date || "9").localeCompare(b.date || "9"));
    $("#decision-list").innerHTML = list.length ? list.map((d, i) => {
      const r = rel(d.date);
      const label = r.cls === "late" ? r.text : d.date ? `by ${fmt(d.date, { month: "short", day: "numeric" })}` : "no date";
      return `<li class="dcard reveal" style="--d:${i * 60}ms">
        <div class="dcard-top"><span class="who">${esc(d.who || "")}</span><span class="due ${r.cls}">${esc(label)}</span></div>
        <h3>${esc(d.title)}</h3>
        ${d.notes ? `<p>${esc(d.notes)}</p>` : ""}
      </li>`;
    }).join("") : `<li class="empty">Nothing waiting on a decision here.</li>`;
  }

  function renderMilestones() {
    const ms = [...(state.data.milestones || [])].sort((a, b) => (a.date || "9").localeCompare(b.date || "9"));
    const nextIdx = ms.findIndex((m) => !isDone(m.status));
    $("#milestones").innerHTML = ms.map((m, i) => {
      const done = isDone(m.status);
      const r = rel(m.date);
      const cls = ["ms", "reveal", done ? "done" : "", i === nextIdx ? "next" : "", !done && r.cls === "late" ? "late" : "", i === ms.length - 1 ? "launch" : ""].join(" ");
      return `<li class="${cls}" style="--d:${i * 50}ms">
        <div class="ms-date"><span>${esc(fmt(m.date))}</span>${done ? "<span>done</span>" : `<span class="rel">${esc(r.text)}</span>`}${i === nextIdx ? '<span class="rel">· up next</span>' : ""}</div>
        <h3>${esc(m.title)}</h3>
        <p class="ms-owner">${esc(m.owner || "")}</p>
      </li>`;
    }).join("");
  }

  function renderAreas() {
    const areas = ["All", ...new Set(state.data.tasks.map((t) => t.area))];
    if (!areas.includes(state.area)) state.area = "All";
    $("#areas").innerHTML = areas.map((a) => `<button class="chip" data-area="${esc(a)}" aria-pressed="${a === state.area}">${esc(a)}</button>`).join("");
  }

  const CHEV = '<svg class="chev" viewBox="0 0 24 24" aria-hidden="true"><path d="M6 9l6 6 6-6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';

  function renderTasks() {
    const base = state.data.tasks.filter((t) => mine(t.owner) && (state.area === "All" || t.area === state.area));
    $$("#task-filter button").forEach((b) => {
      const f = b.dataset.f;
      b.setAttribute("aria-selected", f === state.filter);
      const n = base.filter(FILTERS[f]).length;
      b.innerHTML = `${esc(b.dataset.label || b.textContent.replace(/\d+$/, "").trim())}<span class="count">${n}</span>`;
      b.dataset.label = b.dataset.label || b.textContent.replace(/\d+$/, "").trim();
    });
    const list = base.filter(FILTERS[state.filter]).sort(byDue);
    $("#task-empty").hidden = list.length > 0;
    $("#task-list").innerHTML = list.map((t) => {
      const r = rel(t.due);
      const done = isDone(t.status);
      const when = t.due ? `${fmt(t.due)} · <span class="${done ? "" : r.cls}">${esc(done ? "done" : r.text)}</span>` : "ongoing";
      return `<li class="task ${done ? "is-done" : ""}"><details>
        <summary>
          <span class="dot ${statusCls(t.status)}" aria-hidden="true"></span>
          <span><span class="t-title">${esc(t.title)}</span><span class="t-meta">${esc(t.owner)} · ${when}</span></span>
          ${CHEV}
        </summary>
        <div class="t-body">
          <div class="tags"><span class="tag ${statusCls(t.status)}">${esc(t.status)}</span><span class="tag">${esc(t.area)}</span></div>
          ${t.notes ? `<p>${esc(t.notes)}</p>` : ""}
        </div>
      </details></li>`;
    }).join("");
  }

  function renderRisks() {
    const order = { high: 0, medium: 1, low: 2 };
    const pool = isExec() ? state.data.risks.filter((r) => r.impact.toLowerCase() === "high") : state.data.risks.filter((r) => mine(r.owner));
    const list = pool.sort((a, b) => (order[a.impact.toLowerCase()] ?? 3) - (order[b.impact.toLowerCase()] ?? 3));
    $("#risk-list").innerHTML = list.length ? list.map((r, i) => `<li class="risk reveal" style="--d:${i * 60}ms">
        <div class="risk-top"><span class="impact ${esc(r.impact.toLowerCase())}"><span class="bars"><i></i><i></i><i></i></span>${esc(r.impact)}</span></div>
        <h3>${esc(r.title)}</h3>
        ${r.plan ? `<p>${esc(r.plan)}</p>` : ""}
        ${r.owner ? `<span class="owner">Owner: ${esc(r.owner)}</span>` : ""}
      </li>`).join("") : `<li class="risk"><p>No open risks for this view.</p></li>`;
  }

  function renderMade() {
    const list = [...state.data.decisions.made].sort((a, b) => (b.date || "").localeCompare(a.date || ""));
    $("#made-count").textContent = `${list.length} decisions`;
    $("#made-list").innerHTML = list.map((d) => `<li>
      <span class="when">${esc(d.date ? fmt(d.date, { month: "short", day: "numeric" }) : d.dateText || "")}</span>
      <span class="what">${esc(d.title)}${d.notes ? `<small>${esc(d.notes)}</small>` : ""}</span>
    </li>`).join("");
  }

  /* ---------- Leads view: health and blockers ---------- */
  const AREA_NAMES = { Agents: "Security agent", Store: "Store submission", Website: "Website", Support: "Ticketing system", "Next modules": "Next modules" };
  const daysLate = (s) => -diff(s);
  // Stuck only matters to the leads if it's due soon; something waiting by design months out isn't a blocker yet.
  // Launch-day tasks (due on or after launch) are waiting by design, not blockers.
  const stuckNow = (t) => {
    if (!isStuck(t)) return false;
    const launch = state.data.launch && state.data.launch.date;
    if (t.due && launch && t.due >= launch) return false;
    return !t.due || diff(t.due) <= 21;
  };
  const firstSentence = (s) => (s || "").split(/(?<=[.!?])\s/)[0];

  // Team blockers: anything late or stuck that isn't on the leads themselves
  // and isn't Kazim's own learning or PM admin.
  // Accountability: who owes what. Late items sit with their owner. Stuck items sit with
  // whoever they're waiting on (a teammate named in the note, or the CEO's own decisions).
  const TEAM = ["Shaheer", "Shahzain", "Tauseeq", "Haris", "Awais", "Nasir", "Kazim"];
  const CEO = "You (CEO decisions)";
  function waitingOn(t) {
    const n = t.notes || "";
    if (/store approval|servicenow('s)? review/i.test(n)) return { who: null }; // not chaseable
    const m = n.match(/(waiting on|blocked until|after|from|needs)\b[^.]*/i);
    if (m) {
      const hit = TEAM.find((name) => new RegExp(`\\b${name}`, "i").test(m[0]));
      if (hit) return { who: hit };
      if (/support email|domain|pricing|price|leads/i.test(m[0])) return { who: CEO };
      // "waiting on the demo videos" -> whoever owns the open task about demo videos
      const STOP = ["waiting", "blocked", "until", "after", "needs", "their", "which", "comes", "come", "from", "there"];
      const words = (m[0].toLowerCase().match(/[a-z]{5,}/g) || []).filter((w) => !STOP.includes(w));
      const dep = state.data.tasks.find((o) => o !== t && !isDone(o.status) && words.some((w) => o.title.toLowerCase().includes(w)));
      if (dep) return { who: (dep.owner || "Unassigned").split(/,| and |&/)[0].trim(), dep };
    }
    return { who: (t.owner || "Unassigned").split(/,| and |&/)[0].trim() };
  }
  function blockers() {
    const pool = state.data.tasks.filter((t) => !isDone(t.status) && !leadsOwn(t.owner) && !["Kazim dev", "PM"].includes(t.area));
    const late = pool.filter(isLate);
    const stuck = pool.filter((t) => !isLate(t) && stuckNow(t));
    const groups = new Map();
    const group = (who) => { if (!groups.has(who)) groups.set(who, { who, items: [] }); return groups.get(who); };
    late.forEach((t) => group((t.owner || "Unassigned").split(/,| and |&/)[0].trim()).items.push({ ...t, kind: "late", holding: [] }));
    stuck.forEach((t) => {
      const { who, dep } = waitingOn(t);
      if (!who) return;
      const g = group(who);
      if (dep) {
        // Show what this person owes, and what it's holding up.
        let item = g.items.find((i) => i.title === dep.title);
        if (!item) { item = { ...dep, kind: isLate(dep) ? "late" : "owes", holding: [] }; g.items.push(item); }
        item.holding.push(t.title);
        return;
      }
      if (who === CEO) {
        // Name the CEO's own open decisions this is waiting on.
        const n = (t.notes || "").toLowerCase();
        const keys = ["support email", "domain", "pric"].filter((k) => n.includes(k));
        const asks = leadItems().filter((d) => keys.some((k) => d.title.toLowerCase().includes(k))).map((d) => d.title.split(/[:.]/)[0].replace(/ needed to sign up.*$/i, "").trim());
        const title = asks.length ? asks.join(" + ") : t.title;
        let item = g.items.find((i) => i.title === title);
        if (!item) { item = { title, kind: "waiting", holding: [] }; g.items.push(item); }
        if (asks.length) item.holding.push(t.title);
        return;
      }
      const owed = g.items.find((i) => i.kind === "late");
      if (owed) owed.holding.push(t.title);
      else g.items.push({ ...t, kind: "waiting", holding: [] });
    });
    (state.data.milestones || []).filter((m) => !isDone(m.status) && m.date && diff(m.date) < 0)
      .forEach((m) => group((m.owner || "Team").split(/,| and |&/)[0].trim()).items.push({ title: m.title, due: m.date, kind: "late", milestone: true, holding: [] }));
    return [...groups.values()].filter((g) => g.items.length)
      .sort((a, b) => maxLate(b) - maxLate(a) || b.items.length - a.items.length);
  }
  const maxLate = (g) => Math.max(0, ...g.items.filter((i) => i.kind === "late").map((i) => daysLate(i.due)));
  const isLateItem = (t) => (t.due && diff(t.due) < 0 ? 1 : 0);

  function areaHealth() {
    return Object.entries(AREA_NAMES).map(([area, name]) => {
      const items = state.data.tasks.filter((t) => t.area === area);
      if (!items.length) return null;
      const open = items.filter((t) => !isDone(t.status));
      const late = open.filter(isLate).length;
      const stuck = open.filter((t) => stuckNow(t) && !isLate(t)).length;
      const next = open.filter((t) => t.due && diff(t.due) >= 0).sort(byDue)[0];
      const status = !open.length ? "done" : late ? "off" : stuck ? "risk" : "on";
      const bits = [];
      if (late) bits.push(`${late} late`);
      if (stuck) bits.push(`${stuck} stuck`);
      if (!late && !stuck && open.length) bits.push("All on schedule");
      if (!open.length) bits.push("Finished");
      if (next) bits.push(`next due ${fmt(next.due, { month: "short", day: "numeric" })}`);
      return { name, status, line: bits.join(" · ") };
    }).filter(Boolean);
  }

  function overall() {
    const ms = state.data.milestones || [];
    const missed = ms.filter((m) => !isDone(m.status) && m.date && diff(m.date) < 0);
    const items = blockers().flatMap((g) => g.items);
    const late = items.filter((x) => x.kind === "late").length;
    const stuck = items.length - late;
    const overdueAsks = leadItems().filter((d) => d.date && diff(d.date) < 0).length;
    const next = ms.filter((m) => !isDone(m.status)).sort((x, y) => (x.date || "9").localeCompare(y.date || "9"))[0];
    if (missed.length) return { cls: "off", label: "Behind", text: `${missed.length} milestone${missed.length > 1 ? "s" : ""} missed. The launch date needs a second look.` };
    if (late || stuck || overdueAsks) {
      const parts = [];
      if (late) parts.push(`${late} late`);
      if (stuck) parts.push(`${stuck} stuck`);
      if (overdueAsks) parts.push(`${overdueAsks} of your decisions overdue`);
      return { cls: "risk", label: "At risk", text: `${parts.join(", ")}. No milestone missed yet${next ? `; next up is "${next.title}" on ${fmt(next.date, { month: "short", day: "numeric" })}` : ""}.` };
    }
    return { cls: "on", label: "On track", text: "Nothing late, nothing stuck. Every milestone is on schedule." };
  }

  function renderExec() {
    const o = overall();
    const statusCard = $(".stat-status");
    statusCard.classList.remove("st-on", "st-risk", "st-off");
    statusCard.classList.add(`st-${o.cls}`);
    $("#x-status").textContent = o.label;
    $("#x-needs").textContent = leadItems().length;
    const b = blockers();
    const ms = state.data.milestones || [];
    $("#x-ms").textContent = `${ms.filter((m) => isDone(m.status)).length}/${ms.length}`;

    $("#health-summary").innerHTML = `<strong>${esc(o.label)}.</strong> ${esc(o.text)}`;
    $("#health-list").innerHTML = areaHealth().map((h, i) => `<li class="hrow reveal" style="--d:${i * 50}ms">
        <h3>${esc(h.name)}</h3>
        <span class="pill ${h.status}">${{ on: "On track", risk: "At risk", off: "Behind", done: "Done" }[h.status]}</span>
        <p>${esc(h.line)}</p>
      </li>`).join("");

    $("#blocker-list").innerHTML = b.length ? b.map((g, i) => {
      const lateN = g.items.filter((x) => x.kind === "late").length;
      const head = lateN ? `${lateN} overdue${maxLate(g) ? ` · up to ${maxLate(g)} day${maxLate(g) > 1 ? "s" : ""} late` : ""}` : "holding things up";
      return `<li class="owe reveal ${lateN ? "late" : ""}" style="--d:${i * 60}ms">
        <div class="owe-head"><h3>${esc(g.who)}</h3><span class="why">${esc(head)}</span></div>
        <ul>${g.items.map((t) => {
          const tag = t.kind === "late" ? `${daysLate(t.due)} day${daysLate(t.due) > 1 ? "s" : ""} late`
            : t.kind === "owes" ? `due ${fmt(t.due, { month: "short", day: "numeric" })}`
            : g.who === CEO ? "needs your call" : (t.owner || "").includes(g.who) ? "stuck" : "others waiting on this";
          return `<li><span class="owe-tag ${t.kind}">${esc(tag)}</span><span class="owe-what">${esc(t.title)}${t.kind === "waiting" && g.who !== CEO && !(t.owner || "").includes(g.who) ? ` <small>(${esc(t.owner)} is waiting)</small>` : ""}</span>
            ${t.holding.length ? `<span class="owe-hold">Holding up: ${esc(t.holding.join("; "))}</span>` : ""}</li>`;
        }).join("")}</ul>
      </li>`;
    }).join("") : `<li class="allclear">Nobody's late on anything. Nothing to chase.</li>`;
    const owed = b.reduce((n, g) => n + g.items.length, 0);
    $("#x-blockers").textContent = owed;
  }

  /* ---------- Layout per view ---------- */
  const TEAM_ORDER = ["#overview", ".stats-team", "#decide", "#path", "#tasks", "#risks", "#decided"];
  const EXEC_ORDER = ["#overview", ".stats-exec", "#health", "#blockers", "#decide", "#path", "#risks", "#decided"];
  const TEAM_TABS = [["overview", "Overview"], ["decide", "Decide"], ["tasks", "Work"], ["risks", "Risks"]];
  const EXEC_TABS = [["overview", "Overview"], ["health", "On track?"], ["blockers", "Chase"], ["decide", "Needs you"]];

  function layout() {
    const exec = isExec();
    document.body.classList.toggle("exec", exec);
    const app = $("#app"), foot = $(".foot");
    (exec ? EXEC_ORDER : TEAM_ORDER).forEach((sel) => { const el = $(sel); if (el) app.insertBefore(el, foot); });
    let n = 0;
    $$(".num", app).forEach((el) => {
      const sec = el.closest("section");
      if (sec && getComputedStyle(sec).display !== "none") el.textContent = String(++n).padStart(2, "0");
    });
    $("#risks-h").innerHTML = exec ? 'Biggest <span class="hlw">risks</span>' : 'What could <span class="hlw">slip</span>';
    $(".tabbar").innerHTML = (exec ? EXEC_TABS : TEAM_TABS).map(([id, label]) => `<a href="#${id}" data-tab="${id}">${label}</a>`).join("");
    $(".tabbar a").classList.add("active");
  }

  function renderAll() {
    layout();
    renderHero();
    renderViewAs();
    renderStats();
    renderDecisions();
    renderMilestones();
    renderAreas();
    renderTasks();
    renderRisks();
    renderMade();
    if (isExec()) renderExec();
    observeReveals();
  }

  /* ---------- Motion ---------- */
  function countUp(el, to) {
    if (reduceMotion || to === 0) { el.textContent = to; return; }
    const start = performance.now(), dur = 900;
    const tick = (now) => {
      const p = Math.min((now - start) / dur, 1);
      const eased = 1 - Math.pow(1 - p, 4);
      el.textContent = Math.round(to * eased);
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }

  let revealObs;
  function observeReveals() {
    const els = $$(".reveal:not(.in)");
    if (reduceMotion || !("IntersectionObserver" in window)) { els.forEach((e) => e.classList.add("in")); return; }
    revealObs ??= new IntersectionObserver((entries) => {
      entries.forEach((e) => { if (e.isIntersecting) { e.target.classList.add("in"); revealObs.unobserve(e.target); } });
    }, { rootMargin: "0px 0px -8% 0px" });
    els.forEach((e) => revealObs.observe(e));
    setTimeout(() => els.forEach((e) => e.classList.add("in")), 3000);
  }

  function watchTabs() {
    const obs = new IntersectionObserver((entries) => {
      entries.forEach((e) => {
        if (!e.isIntersecting) return;
        const tabs = $$(".tabbar a");
        if (tabs.some((a) => a.dataset.tab === e.target.id)) tabs.forEach((a) => a.classList.toggle("active", a.dataset.tab === e.target.id));
      });
    }, { rootMargin: "-40% 0px -55% 0px" });
    ["overview", "decide", "health", "blockers", "path", "tasks", "risks"].forEach((id) => { const s = document.getElementById(id); if (s) obs.observe(s); });
  }

  /* ---------- Events ---------- */
  function bind() {
    document.addEventListener("click", (e) => {
      const view = e.target.closest("[data-view]");
      if (view) { state.view = view.dataset.view; store.set(STORE_VIEW, state.view); renderAll(); return; }
      const area = e.target.closest("[data-area]");
      if (area) { state.area = area.dataset.area; renderAreas(); renderTasks(); return; }
      const f = e.target.closest("#task-filter button");
      if (f) { state.filter = f.dataset.f; renderTasks(); return; }
      const jump = e.target.closest("[data-jump]");
      if (jump) {
        const j = jump.dataset.jump;
        if (["decide", "blockers", "path"].includes(j)) { $(`#${j}`).scrollIntoView(); return; }
        state.filter = j === "blocked" ? "stuck" : j;
        state.area = "All";
        renderAreas(); renderTasks();
        $("#tasks").scrollIntoView();
      }
    });
    $("#lock").addEventListener("click", () => { store.del(STORE_PW); location.reload(); });
  }

  /* ---------- Gate ---------- */
  async function open(password, remember) {
    const [wrapped, payload] = await Promise.all([fetchJSON(KEY_URL), fetchJSON(DATA_URL)]);
    const privateKey = await unlockPrivateKey(wrapped, password);
    const data = await decrypt(payload, privateKey);
    if (remember) store.set(STORE_PW, password);
    state.data = data;
    $("#gate").hidden = true;
    $("#app").hidden = false;
    renderAll();
    watchTabs();
  }

  function initGate() {
    const form = $("#gate-form"), err = $("#gate-error"), btn = $("#unlock");
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      err.hidden = true;
      btn.disabled = true; btn.textContent = "Unlocking…";
      try {
        await open($("#pw").value, $("#remember").checked);
      } catch (ex) {
        err.textContent = ex.message === "load" ? "Couldn't load the board. Check your connection and try again." : "That password didn't work.";
        err.hidden = false;
        form.classList.remove("shake"); void form.offsetWidth; form.classList.add("shake");
        btn.disabled = false; btn.textContent = "Unlock";
      }
    });
    const saved = store.get(STORE_PW);
    if (saved) open(saved, true).catch(() => store.del(STORE_PW));
    else $("#pw").focus();
  }

  bind();
  initGate();
})();

/* .NET assembly browser.

   Upload a .dll/.exe, see where its interesting calls are, and open any
   method as annotated IL. Talks to app.js only through window.AsmApp. */
(() => {
  'use strict';

  const esc = (s) => String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const RANK = { warning: 0, notable: 1, info: 2 };
  const MAX_FLAT = 400;

  const st = {
    file: null, ov: null, byId: new Map(), findings: new Map(), graph: null,
    query: '', flaggedOnly: false, finding: null, current: null,
  };
  const panel = () => document.getElementById('methodsPanel');

  async function upload(file) {
    const form = new FormData();
    form.append('file', file);
    const res = await fetch('/api/dotnet/load', { method: 'POST', body: form });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `Upload failed (${res.status})`);
    return data;
  }

  async function open(file) {
    st.file = file;
    const tab = document.getElementById('modeMethods');
    tab.hidden = false;
    window.AsmApp.setMode('methods');
    panel().innerHTML = `<div class="empty"><strong>Reading ${esc(file.name)}…</strong>`
      + 'Every method is decoded and scanned; large assemblies take a few seconds.</div>';
    try {
      const data = await upload(file);
      st.ov = data;
      st.byId = new Map(data.methods.map((m) => [m.id, m]));
      st.findings = new Map(data.findings.map((f) => [f.id, f]));
      st.query = '';
      st.finding = null;
      st.flaggedOnly = data.counts.flagged > 0;
      render();
    } catch (err) {
      panel().innerHTML = `<div class="error-box">${esc(err.message)}</div>`;
    }
  }

  /* ---- rendering ------------------------------------------------------ */
  function render() {
    const ov = st.ov;
    const c = ov.counts;
    const findings = ov.findings.map((f) => `
      <button class="finding-chip sev-${esc(f.severity)}${st.finding === f.id ? ' active' : ''}"
              data-finding="${esc(f.id)}" title="${esc(f.description)}">
        ${esc(f.name)} <span>${f.method_count}</span>
      </button>`).join('');

    const pinvokes = ov.pinvokes.length ? `
      <details class="pinvoke-list">
        <summary>${ov.pinvokes.length} native import${ov.pinvokes.length === 1 ? '' : 's'} (P/Invoke)</summary>
        <ul>${ov.pinvokes.map((p) => `
          <li><button class="link" data-method="${p.method}">${esc(p.name)}</button>
              <span>${esc(p.dll)}</span></li>`).join('')}</ul>
      </details>` : '';

    panel().innerHTML = `
      <div class="asm-head">
        <div class="asm-title">${esc(ov.name)} <span>${esc(ov.version)} · ${esc(ov.kind)}</span></div>
        <div class="asm-file">${esc(ov.filename || '')}</div>
        <div class="asm-counts">
          <span><b>${c.types}</b> types</span>
          <span><b>${c.methods}</b> methods</span>
          <span><b>${c.flagged}</b> flagged</span>
          <span><b>${c.pinvokes}</b> P/Invoke</span>
          <span><b>${c.references}</b> references</span>
          ${ov.reachability ? `<span><b>${ov.reachability.flagged_reachable}</b> flagged and reachable from the entry point</span>` : ''}
        </div>
        ${ov.references.length ? `<div class="asm-refs">References: ${ov.references.map(esc).join(', ')}</div>` : ''}
      </div>
      ${findings ? `<div class="finding-row">${findings}</div>` : '<p class="asm-quiet">No rules matched anywhere in this assembly.</p>'}
      ${pinvokes}
      <div class="method-controls">
        <input type="search" id="methodSearch" placeholder="Filter methods by name or type"
               value="${esc(st.query)}" aria-label="Filter methods">
        <label><input type="checkbox" id="flaggedOnly" ${st.flaggedOnly ? 'checked' : ''}> flagged only</label>
      </div>
      <div class="method-list" id="methodList"></div>`;
    renderList();
  }

  function matches(m) {
    if (st.flaggedOnly && !m.findings.length) return false;
    if (st.finding && !m.findings.includes(st.finding)) return false;
    if (st.query) {
      const q = st.query.toLowerCase();
      return m.name.toLowerCase().includes(q) || m.type.toLowerCase().includes(q)
        || m.display.toLowerCase().includes(q);
    }
    return true;
  }

  function methodRow(m, showType) {
    const sev = m.severity ? `<i class="sev-dot sev-${esc(m.severity)}" title="${esc(m.severity)}"></i>`
                           : '<i class="sev-dot"></i>';
    const tags = [];
    if (m.static) tags.push('static');
    if (m.reachable === false && m.findings.length) tags.push('not reached');
    if (m.pinvoke) tags.push('P/Invoke');
    else if (!m.has_body) tags.push('no body');
    const names = m.findings.map((id) => (st.findings.get(id) || {}).name || id);
    const shortType = m.type.split('/').pop().split('.').pop();
    const tip = `${m.type}::${m.display}` + (names.length ? `\n${names.join(', ')}` : '');
    return `<button class="method-row${st.current === m.id ? ' active' : ''}" data-method="${m.id}"
                    title="${esc(tip)}">
        ${sev}
        <span class="m-text">${showType ? `<span class="m-type">${esc(shortType)}</span>` : ''}${esc(m.label)}<span class="m-ret">${esc(m.returns_short)}</span></span>
        ${tags.map((t) => `<span class="m-tag">${t}</span>`).join('')}
        ${m.findings.length ? `<span class="m-count">${m.findings.length}</span>` : ''}
      </button>`;
  }

  function renderList() {
    const list = document.getElementById('methodList');
    if (!list) return;
    const filtering = st.query || st.finding || st.flaggedOnly;

    if (filtering) {
      const hits = st.ov.methods.filter(matches).sort((a, b) =>
        (RANK[a.severity] ?? 3) - (RANK[b.severity] ?? 3) || b.findings.length - a.findings.length);
      list.innerHTML = hits.length
        ? hits.slice(0, MAX_FLAT).map((m) => methodRow(m, true)).join('')
          + (hits.length > MAX_FLAT ? `<p class="asm-quiet">Showing ${MAX_FLAT} of ${hits.length}; narrow the filter.</p>` : '')
        : '<p class="asm-quiet">No methods match.</p>';
      return;
    }

    // Grouped by type; method rows are built only when a type is opened.
    const types = st.ov.types.map((t) => {
      const ms = t.methods.map((id) => st.byId.get(id));
      return { name: t.name, ms, flagged: ms.filter((m) => m.findings.length).length };
    }).sort((a, b) => b.flagged - a.flagged || a.name.localeCompare(b.name));
    list.innerHTML = types.map((t, i) => `
      <details class="type-group" data-type-index="${i}">
        <summary>${esc(t.name)} <span>${t.ms.length}${t.flagged ? ` · ${t.flagged} flagged` : ''}</span></summary>
        <div class="type-methods"></div>
      </details>`).join('');
    list.querySelectorAll('details.type-group').forEach((d) => {
      d.addEventListener('toggle', () => {
        const box = d.querySelector('.type-methods');
        if (d.open && !box.childElementCount) {
          box.innerHTML = types[Number(d.dataset.typeIndex)].ms.map((m) => methodRow(m, false)).join('');
        }
      });
    });
  }

  /* ---- opening a method --------------------------------------------------- */
  async function openMethod(id) {
    if (!st.ov) return;
    const url = `/api/dotnet/${st.ov.sha256}/method/${id}`;
    try {
      let res = await fetch(url);
      if (res.status === 410 && st.file) {      // evicted from the server cache
        await upload(st.file);
        res = await fetch(url);
      }
      const data = await res.json();
      if (!res.ok) { window.AsmApp.toast(data.error || 'Could not open that method.'); return; }
      try {
        const g = await fetch(`/api/dotnet/${st.ov.sha256}/calls/${id}`);
        st.graph = g.ok ? await g.json() : null;
      } catch { st.graph = null; }
      st.current = id;
      panel().querySelectorAll('.method-row').forEach((r) =>
        r.classList.toggle('active', Number(r.dataset.method) === id));
      window.AsmApp.openListing(data.text, 'cil');
      window.AsmApp.refreshView();
    } catch (err) {
      window.AsmApp.toast(err.message || 'Could not open that method.');
    }
  }

  /* ---- wiring ---------------------------------------------------------------- */
  document.addEventListener('DOMContentLoaded', () => {
    const p = panel();
    if (!p) return;
    p.addEventListener('click', (e) => {
      const method = e.target.closest('[data-method]');
      if (method) { openMethod(Number(method.dataset.method)); return; }
      const chip = e.target.closest('[data-finding]');
      if (chip) {
        st.finding = st.finding === chip.dataset.finding ? null : chip.dataset.finding;
        if (st.finding) st.flaggedOnly = false;
        render();
      }
    });
    p.addEventListener('input', (e) => {
      if (e.target.id === 'methodSearch') { st.query = e.target.value.trim(); renderList(); }
    });
    p.addEventListener('change', (e) => {
      if (e.target.id === 'flaggedOnly') { st.flaggedOnly = e.target.checked; renderList(); }
    });
  });

  window.AsmDotnet = { open, openMethod, currentGraph: () => st.graph };
})();

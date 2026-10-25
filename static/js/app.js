/* Assembly Annotator - front end.
   No framework, no CDN: the whole thing is this file plus one stylesheet. */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const el = {
    code: $('codeInput'), highlight: $('highlight').querySelector('code'),
    gutter: $('gutter'), annotations: $('annotations'), stats: $('statsBar'),
    patternsSection: $('patternsSection'), patternGrid: $('patternGrid'),
    patternCount: $('patternCount'), patternsHead: $('patternsHead'),
    filter: $('filterInput'), filterCount: $('filterCount'),
    analyze: $('analyzeBtn'), clear: $('clearBtn'), sample: $('sampleBtn'),
    expand: $('expandBtn'), toast: $('toast'), detectHint: $('detectHint'),
    arch: $('archSel'), syntax: $('syntaxSel'), verb: $('verbSel'), theme: $('themeSel'),
    splitter: $('splitter'), leftPane: $('leftPane'), panes: $('panes'),
    help: $('helpDialog'),
  };

  const store = {
    get(k, fallback) {
      try { const v = localStorage.getItem('asmann.' + k); return v === null ? fallback : v; }
      catch { return fallback; }
    },
    set(k, v) { try { localStorage.setItem('asmann.' + k, v); } catch { /* private mode */ } },
  };

  let state = { result: null, highlightLines: new Set(), activePattern: null, allOpen: false };

  /* ---- syntax highlighting ---------------------------------------- */
  const MNEMONIC = /^(?:[a-z][a-z0-9.]{1,9})$/i;
  const REGISTER = /^%?(?:[re]?(?:ax|bx|cx|dx|si|di|bp|sp|ip)|[abcd][lh]|r\d{1,2}[dwb]?|[xw]\d{1,2}|[xy]mm\d{1,2}|sp|lr|pc|fp|cpsr)$/i;
  const NUMBER = /^[$#]?-?(?:0x[0-9a-f]+|0b[01]+|\d+h?)$/i;

  // Escapes quotes as well as angle brackets: this output is interpolated into
  // HTML *attributes* too, where a bare `"` would let input inject its own.
  const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ESCAPES[c]);

  function highlightLine(raw) {
    // Split off a trailing comment first so its contents are never re-tokenised.
    let comment = '';
    const cm = raw.match(/(;|\/\/|#(?![0-9a-fx]))/i);
    if (cm) { comment = raw.slice(cm.index); raw = raw.slice(0, cm.index); }

    let out = '';
    // objdump prefix: `  1129:\t55 48 89 e5\t`
    const dump = raw.match(/^(\s*[0-9a-f]{4,16}:\s*)((?:[0-9a-f]{2}\s+)*)/i);
    if (dump && dump[1]) {
      out += `<span class="t-addr">${esc(dump[1] + (dump[2] || ''))}</span>`;
      raw = raw.slice(dump[0].length);
    }

    const tokens = raw.split(/(\s+|,|\[|\]|\(|\)|"[^"]*"|'[^']*')/);
    let seenMnemonic = false;
    for (const tok of tokens) {
      if (!tok) continue;
      if (/^\s+$/.test(tok) || /^[,\[\]()]$/.test(tok)) {
        const cls = /^[\[\]()]$/.test(tok) ? 't-mem' : '';
        out += cls ? `<span class="${cls}">${esc(tok)}</span>` : esc(tok);
        continue;
      }
      if (/^["']/.test(tok)) { out += `<span class="t-str">${esc(tok)}</span>`; continue; }
      if (/:$/.test(tok)) { out += `<span class="t-lbl">${esc(tok)}</span>`; continue; }
      if (NUMBER.test(tok)) { out += `<span class="t-num">${esc(tok)}</span>`; continue; }
      if (REGISTER.test(tok)) { out += `<span class="t-reg">${esc(tok)}</span>`; continue; }
      if (!seenMnemonic && /^\.|^(?:section|segment|global|globl|extern|bits|org|align|db|dw|dd|dq|resb|resd|equ|times)$/i.test(tok)) {
        out += `<span class="t-dir">${esc(tok)}</span>`; seenMnemonic = true; continue;
      }
      if (!seenMnemonic && MNEMONIC.test(tok)) {
        out += `<span class="t-mn">${esc(tok)}</span>`; seenMnemonic = true; continue;
      }
      out += esc(tok);
    }
    if (comment) out += `<span class="t-cmt">${esc(comment)}</span>`;
    return out;
  }

  function renderEditor() {
    const lines = el.code.value.split('\n');
    const cur = currentLineNumber();
    el.highlight.innerHTML = lines.map((line, i) => {
      const n = i + 1;
      const cls = ['hl-line'];
      if (state.highlightLines.has(n)) cls.push('hit');
      if (n === cur) cls.push('cur');
      return `<span class="${cls.join(' ')}">${highlightLine(line) || '&nbsp;'}</span>`;
    }).join('');  // the spans are display:block, so no newline between them
    el.gutter.innerHTML = lines.map((_, i) => {
      const n = i + 1;
      const cls = state.highlightLines.has(n) ? 'hit' : (n === cur ? 'cur' : '');
      return `<div class="${cls}">${n}</div>`;
    }).join('');
    syncScroll();
  }

  function currentLineNumber() {
    const pos = el.code.selectionStart;
    if (pos == null) return -1;
    return el.code.value.slice(0, pos).split('\n').length;
  }

  function syncScroll() {
    const pre = el.highlight.parentElement;
    pre.scrollTop = el.code.scrollTop;
    pre.scrollLeft = el.code.scrollLeft;
    el.gutter.scrollTop = el.code.scrollTop;
  }

  /* ---- analysis ---------------------------------------------------- */
  async function analyze() {
    const code = el.code.value;
    if (!code.trim()) { toast('Nothing to analyze — paste some assembly first.'); return; }
    el.analyze.disabled = true;
    el.analyze.textContent = 'Working…';
    try {
      const res = await fetch('/api/annotate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code, arch: el.arch.value, syntax: el.syntax.value, verbosity: el.verb.value,
        }),
      });
      const data = await res.json();
      if (!res.ok) { showError(data.error || `Request failed (${res.status})`); return; }
      state.result = data;
      state.activePattern = null;
      state.highlightLines = new Set();
      renderStats(data);
      renderAnnotations(data);
      renderPatterns(data);
      renderEditor();
      el.detectHint.textContent = `${data.meta.arch} · ${data.meta.syntax}`;
      store.set('code', code);
    } catch (err) {
      showError(err.message || 'Could not reach the server.');
    } finally {
      el.analyze.disabled = false;
      el.analyze.textContent = 'Analyze';
    }
  }

  function showError(message) {
    el.annotations.innerHTML = `<div class="error-box">${esc(message)}</div>`;
    el.stats.hidden = true;
    el.patternsSection.hidden = true;
  }

  /* ---- stats ------------------------------------------------------- */
  function renderStats(data) {
    const s = data.stats;
    const items = [
      ['instructions', s.instructions],
      ['lines', s.lines],
      ['labels', s.labels],
      ['branches', s.branches],
      ['loops', s.loops],
      ['recognised', s.coverage + '%'],
    ];
    if (s.syscalls.length) items.push(['syscalls', s.syscalls.join(', ')]);
    let html = items.map(([k, v]) =>
      `<div class="stat"><span class="v">${esc(String(v))}</span><span class="k">${k}</span></div>`).join('');
    if (s.warnings.length) {
      html += `<div class="stat warnish"><span class="v">${s.warnings.length}</span><span class="k">flagged</span></div>`;
    }
    const total = s.categories.reduce((a, c) => a + c.count, 0) || 1;
    html += '<div class="catbar">' + s.categories.map((c) =>
      `<span class="seg" style="width:${Math.max(4, (c.count / total) * 180)}px;background:${c.colour}"
             title="${esc(c.label)}: ${c.count}"></span>`).join('') + '</div>';
    el.stats.innerHTML = html;
    el.stats.hidden = false;
  }

  /* ---- annotations -------------------------------------------------- */
  function renderAnnotations(data) {
    const rows = data.annotations.filter((a) => a.kind !== 'blank');
    if (!rows.length) {
      el.annotations.innerHTML = '<div class="empty"><strong>No code found</strong>The input had no instructions, labels or directives.</div>';
      return;
    }
    el.annotations.innerHTML = rows.map(annotationHTML).join('');
    applyFilter();
  }

  function annotationHTML(a) {
    const badges = [];
    if (a.kind === 'instruction') badges.push(`<span class="badge cat">${esc(a.category)}</span>`);
    if (a.loop_header) badges.push('<span class="badge loop">loop head</span>');
    if (a.unreachable) badges.push('<span class="badge dead">unreachable</span>');
    if (a.syscall) badges.push(`<span class="badge sys">${esc(a.syscall)}()</span>`);
    if (a.jump_target) {
      badges.push(`<span class="badge jump" data-goto="${a.jump_target}">`
        + `${a.jump_backward ? '↑' : '↓'} line ${a.jump_target}</span>`);
    }

    const notes = (a.notes || []).map((n) => `<li>${esc(n)}</li>`).join('');
    const detail = a.detail ? `<p>${esc(a.detail)}</p>` : '';
    const flags = a.flags ? `<div class="flags">Flags written: ${esc(a.flags)}</div>` : '';
    const hasDetail = Boolean(detail || notes || flags);

    return `<article class="ann${hasDetail ? ' has-detail' : ''}" data-cat="${esc(a.category)}" data-line="${a.index}"
      data-text="${esc((a.raw + ' ' + a.title + ' ' + a.category + ' ' + (a.notes || []).join(' ')).toLowerCase())}">
      <div class="ann-top">
        <span class="ann-num">${a.index}</span>
        <span class="ann-code">${highlightLine(a.raw.trim())}</span>
        <span class="ann-badges">${badges.join('')}</span>
      </div>
      <div class="ann-title">${esc(a.title)}</div>
      ${hasDetail ? `<div class="ann-detail">${detail}${notes ? `<ul>${notes}</ul>` : ''}${flags}</div>
        <span class="ann-expand">▾</span>` : ''}
    </article>`;
  }

  /* ---- patterns ------------------------------------------------------ */
  function renderPatterns(data) {
    const ps = data.patterns;
    if (!ps.length) {
      el.patternGrid.innerHTML = '<p style="color:var(--text-faint);font-size:.82rem">No patterns matched this listing.</p>';
      el.patternCount.textContent = '';
      el.patternsSection.hidden = false;
      return;
    }
    el.patternCount.textContent = `${ps.length} found`;
    el.patternGrid.innerHTML = ps.map((p) => `
      <article class="pattern" data-sev="${esc(p.severity)}" data-id="${esc(p.id)}"
               data-lines="${p.lines.join(',')}" tabindex="0" role="button">
        <h3>${esc(p.name)} <span class="sev">${esc(p.severity)}</span></h3>
        <p>${esc(p.description)}</p>
        <div class="lines">Line${p.lines.length > 1 ? 's' : ''}
          <b>${p.lines.slice(0, 10).join(', ')}${p.lines.length > 10 ? '…' : ''}</b></div>
      </article>`).join('');
    el.patternsSection.hidden = false;
  }

  function selectPattern(card) {
    const id = card.dataset.id;
    document.querySelectorAll('.pattern').forEach((c) => c.classList.remove('active'));
    if (state.activePattern === id) {
      state.activePattern = null;
      state.highlightLines = new Set();
    } else {
      state.activePattern = id;
      card.classList.add('active');
      state.highlightLines = new Set(card.dataset.lines.split(',').filter(Boolean).map(Number));
    }
    document.querySelectorAll('.ann').forEach((a) => {
      a.classList.toggle('hit', state.highlightLines.has(Number(a.dataset.line)));
    });
    renderEditor();
    const first = [...state.highlightLines][0];
    if (first) scrollToLine(first);
  }

  function scrollToLine(n) {
    const target = el.annotations.querySelector(`.ann[data-line="${n}"]`);
    if (!target) return;
    target.scrollIntoView({ behavior: 'smooth', block: 'center' });
    document.querySelectorAll('.ann.active').forEach((a) => a.classList.remove('active'));
    target.classList.add('active');
  }

  /* ---- filter --------------------------------------------------------- */
  function applyFilter() {
    const q = el.filter.value.trim().toLowerCase();
    const cards = el.annotations.querySelectorAll('.ann');
    let shown = 0;
    cards.forEach((c) => {
      const match = !q || c.dataset.text.includes(q);
      c.hidden = !match;
      if (match) shown++;
    });
    el.filterCount.textContent = q ? `${shown} / ${cards.length}` : `${cards.length} lines`;
  }

  /* ---- export ---------------------------------------------------------- */
  async function exportAs(fmt) {
    const code = el.code.value;
    if (!code.trim()) { toast('Nothing to export yet.'); return; }

    if (fmt === 'copy') {
      if (!state.result) { toast('Run an analysis first.'); return; }
      const text = state.result.annotations
        .filter((a) => a.kind !== 'blank')
        .map((a) => `${String(a.index).padStart(4)} | ${a.raw.trim().padEnd(32)} | ${a.title}`)
        .join('\n');
      try {
        await navigator.clipboard.writeText(text);
        toast('Annotations copied to the clipboard.');
      } catch { toast('Clipboard blocked by the browser.'); }
      return;
    }

    try {
      const res = await fetch(`/api/export/${fmt}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, arch: el.arch.value, syntax: el.syntax.value, verbosity: el.verb.value }),
      });
      if (!res.ok) { toast('Export failed.'); return; }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `analysis.${fmt}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast(`Downloaded analysis.${fmt}`);
    } catch { toast('Export failed.'); }
  }

  /* ---- misc UI --------------------------------------------------------- */
  let toastTimer;
  function toast(message) {
    el.toast.textContent = message;
    el.toast.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.toast.classList.remove('show'), 2600);
  }

  async function loadExample(id) {
    try {
      const res = await fetch(`/api/examples/${id}`);
      if (!res.ok) { toast('Could not load that example.'); return; }
      const ex = await res.json();
      el.code.value = ex.code;
      el.arch.value = '';
      el.syntax.value = '';
      renderEditor();
      analyze();
    } catch { toast('Could not load that example.'); }
  }

  function closeMenus() {
    document.querySelectorAll('.menu.open').forEach((m) => {
      m.classList.remove('open');
      const b = m.querySelector('.btn');
      if (b) b.setAttribute('aria-expanded', 'false');
    });
  }

  /* ---- splitter -------------------------------------------------------- */
  function initSplitter() {
    let dragging = false;
    const move = (clientX) => {
      const rect = el.panes.getBoundingClientRect();
      const pct = Math.min(75, Math.max(22, ((clientX - rect.left) / rect.width) * 100));
      el.leftPane.style.flex = `0 0 ${pct}%`;
      store.set('split', String(pct));
    };
    el.splitter.addEventListener('pointerdown', (e) => {
      dragging = true;
      el.splitter.classList.add('active');
      el.splitter.setPointerCapture(e.pointerId);
    });
    el.splitter.addEventListener('pointermove', (e) => { if (dragging) move(e.clientX); });
    el.splitter.addEventListener('pointerup', (e) => {
      dragging = false;
      el.splitter.classList.remove('active');
      el.splitter.releasePointerCapture(e.pointerId);
    });
    el.splitter.addEventListener('keydown', (e) => {
      const cur = parseFloat(store.get('split', '44'));
      if (e.key === 'ArrowLeft') { el.leftPane.style.flex = `0 0 ${cur - 3}%`; store.set('split', String(cur - 3)); }
      if (e.key === 'ArrowRight') { el.leftPane.style.flex = `0 0 ${cur + 3}%`; store.set('split', String(cur + 3)); }
    });
    const saved = store.get('split', null);
    if (saved) el.leftPane.style.flex = `0 0 ${saved}%`;
  }

  /* ---- wiring ---------------------------------------------------------- */
  function init() {
    el.theme.value = store.get('theme', 'terminal');
    document.documentElement.dataset.theme = el.theme.value;
    el.verb.value = store.get('verbosity', 'normal');
    el.code.value = store.get('code', '');

    el.theme.addEventListener('change', () => {
      document.documentElement.dataset.theme = el.theme.value;
      store.set('theme', el.theme.value);
    });
    el.verb.addEventListener('change', () => {
      store.set('verbosity', el.verb.value);
      if (state.result) analyze();
    });
    el.arch.addEventListener('change', () => { if (state.result) analyze(); });
    el.syntax.addEventListener('change', () => { if (state.result) analyze(); });

    el.analyze.addEventListener('click', analyze);
    el.clear.addEventListener('click', () => {
      el.code.value = '';
      state.result = null;
      state.highlightLines = new Set();
      el.annotations.innerHTML = '<div class="empty"><strong>Cleared</strong>Paste a new listing and press <kbd>Ctrl</kbd>+<kbd>Enter</kbd>.</div>';
      el.stats.hidden = true;
      el.patternsSection.hidden = true;
      el.detectHint.textContent = '';
      store.set('code', '');
      renderEditor();
      el.code.focus();
    });
    el.sample.addEventListener('click', () => {
      const first = document.querySelector('[data-example]');
      if (first) loadExample(first.dataset.example);
    });

    el.code.addEventListener('input', renderEditor);
    el.code.addEventListener('scroll', syncScroll);
    el.code.addEventListener('click', renderEditor);
    el.code.addEventListener('keyup', (e) => {
      if (e.key.startsWith('Arrow') || e.key === 'Home' || e.key === 'End') renderEditor();
    });
    el.code.addEventListener('keydown', (e) => {
      if (e.key === 'Tab') {
        e.preventDefault();
        const s = el.code.selectionStart;
        const en = el.code.selectionEnd;
        el.code.setRangeText('    ', s, en, 'end');
        renderEditor();
      }
    });

    el.filter.addEventListener('input', applyFilter);

    el.expand.addEventListener('click', () => {
      state.allOpen = !state.allOpen;
      document.querySelectorAll('.ann.has-detail').forEach((a) => a.classList.toggle('open', state.allOpen));
      el.expand.textContent = state.allOpen ? 'Collapse all' : 'Expand all';
    });

    el.annotations.addEventListener('click', (e) => {
      const jump = e.target.closest('[data-goto]');
      if (jump) { e.stopPropagation(); scrollToLine(Number(jump.dataset.goto)); return; }
      const card = e.target.closest('.ann.has-detail');
      if (card) card.classList.toggle('open');
    });

    el.patternGrid.addEventListener('click', (e) => {
      const card = e.target.closest('.pattern');
      if (card) selectPattern(card);
    });
    el.patternGrid.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        const card = e.target.closest('.pattern');
        if (card) { e.preventDefault(); selectPattern(card); }
      }
    });
    el.patternsHead.addEventListener('click', () => {
      const sec = el.patternsSection;
      sec.classList.toggle('collapsed');
      el.patternsHead.setAttribute('aria-expanded', String(!sec.classList.contains('collapsed')));
    });

    document.querySelectorAll('.menu > .btn').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const menu = btn.parentElement;
        const open = menu.classList.contains('open');
        closeMenus();
        menu.classList.toggle('open', !open);
        btn.setAttribute('aria-expanded', String(!open));
      });
    });
    document.addEventListener('click', closeMenus);
    document.querySelectorAll('[data-example]').forEach((b) =>
      b.addEventListener('click', () => { closeMenus(); loadExample(b.dataset.example); }));
    document.querySelectorAll('[data-export]').forEach((b) =>
      b.addEventListener('click', () => { closeMenus(); exportAs(b.dataset.export); }));

    $('helpBtn').addEventListener('click', () => el.help.showModal());
    $('helpClose').addEventListener('click', () => el.help.close());

    document.addEventListener('keydown', (e) => {
      const mod = e.ctrlKey || e.metaKey;
      if (mod && e.key === 'Enter') { e.preventDefault(); analyze(); }
      else if (mod && e.key.toLowerCase() === 'k') { e.preventDefault(); el.filter.focus(); el.filter.select(); }
      else if (mod && e.key === '/') { e.preventDefault(); el.expand.click(); }
      else if (e.key === 'Escape' && !el.help.open) {
        el.filter.value = '';
        applyFilter();
        state.highlightLines = new Set();
        state.activePattern = null;
        document.querySelectorAll('.pattern.active, .ann.active, .ann.hit')
          .forEach((n) => n.classList.remove('active', 'hit'));
        renderEditor();
      }
    });

    initSplitter();
    renderEditor();
    if (el.code.value.trim()) analyze();
  }

  document.addEventListener('DOMContentLoaded', init);
})();

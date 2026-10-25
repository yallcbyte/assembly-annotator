/* Graph and stack-frame views.

   Both render to inline SVG so they inherit the page's theme colours and stay
   crisp at any zoom. Kept apart from app.js because they are self-contained:
   each takes the analysis result and a container, and reports clicks back
   through a callback. */
(() => {
  'use strict';

  const SVG_NS = 'http://www.w3.org/2000/svg';
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const el = (name, attrs = {}, text) => {
    const node = document.createElementNS(SVG_NS, name);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    if (text != null) node.textContent = text;
    return node;
  };

  /* ---- control-flow graph ------------------------------------------ */

  const NODE_W = 260;
  const LINE_H = 16;
  const PAD_Y = 26;
  const GAP_X = 34;
  const GAP_Y = 54;
  const MAX_ROWS = 9;   // instructions shown per block before eliding

  function layer(blocks, edges) {
    // Longest-path layering, ignoring back edges so loops do not run away.
    const depth = new Map(blocks.map((b) => [b.id, 0]));
    const forward = edges.filter((e) => e.to != null && !e.backward && e.to !== e.from);
    for (let pass = 0; pass < blocks.length + 1; pass++) {
      let moved = false;
      for (const e of forward) {
        const want = depth.get(e.from) + 1;
        if (want > depth.get(e.to)) { depth.set(e.to, want); moved = true; }
      }
      if (!moved) break;
    }
    return depth;
  }

  function buildLayout(blocks, edges, lineText) {
    const depth = layer(blocks, edges);
    const rows = new Map();
    for (const b of blocks) {
      const d = depth.get(b.id) || 0;
      if (!rows.has(d)) rows.set(d, []);
      rows.get(d).push(b);
    }

    const placed = new Map();
    let y = PAD_Y;
    let maxW = 0;
    const sortedDepths = [...rows.keys()].sort((a, b) => a - b);

    for (const d of sortedDepths) {
      const row = rows.get(d).sort((a, b) => a.id - b.id);
      const rowW = row.length * NODE_W + (row.length - 1) * GAP_X;
      maxW = Math.max(maxW, rowW);
      let rowH = 0;
      row.forEach((b, i) => {
        const shown = Math.min(b.lines.length, MAX_ROWS);
        const h = PAD_Y + shown * LINE_H + (b.lines.length > MAX_ROWS ? LINE_H : 0) + 10;
        rowH = Math.max(rowH, h);
        placed.set(b.id, { block: b, x: i * (NODE_W + GAP_X), y, w: NODE_W, h });
      });
      y += rowH + GAP_Y;
    }

    // Centre each row inside the widest row.
    for (const d of sortedDepths) {
      const row = rows.get(d);
      const rowW = row.length * NODE_W + (row.length - 1) * GAP_X;
      const shift = (maxW - rowW) / 2;
      for (const b of row) placed.get(b.id).x += shift;
    }

    return { placed, width: maxW + PAD_Y * 2, height: y };
  }

  function edgePath(a, b, kind, backward) {
    if (!a || !b) return '';
    if (a === b) {
      // Self loop: a lobe off the right-hand side.
      const x = a.x + a.w, y = a.y + a.h / 2;
      return `M ${x} ${y - 10} C ${x + 46} ${y - 30}, ${x + 46} ${y + 30}, ${x} ${y + 10}`;
    }
    const sx = a.x + a.w / 2;
    const sy = backward ? a.y : a.y + a.h;
    const tx = b.x + b.w / 2;
    const ty = backward ? b.y + b.h : b.y;
    if (backward) {
      if (Math.abs(sx - tx) > 40) {
        // Target sits off to one side: a direct curve upward is clearest.
        // Shift both ends off-centre so it does not sit on top of the
        // fall-through edge that usually joins the same two blocks.
        const off = tx > sx ? 46 : -46;
        const x1 = sx + off, x2 = tx + off / 2;
        return `M ${x1} ${sy} C ${x1} ${sy - 50}, ${x2} ${ty + 50}, ${x2} ${ty}`;
      }
      // Same column: go round the right-hand edge so the edge does not run
      // back through the blocks between source and target.
      const side = Math.max(a.x + a.w, b.x + b.w) + 30;
      return `M ${a.x + a.w} ${a.y + 14} C ${side} ${a.y + 14}, `
           + `${side} ${b.y + b.h - 14}, ${b.x + b.w} ${b.y + b.h - 14}`;
    }
    const mid = (sy + ty) / 2;
    return `M ${sx} ${sy} C ${sx} ${mid}, ${tx} ${mid}, ${tx} ${ty}`;
  }

  const EDGE_COLOUR = {
    taken: 'var(--cat-arith)',
    fallthrough: 'var(--text-faint)',
    jump: 'var(--cat-data)',
    indirect: 'var(--cat-control)',
  };

  function renderGraph(container, result, onPick) {
    const blocks = (result.cfg && result.cfg.blocks) || [];
    const edges = (result.cfg && result.cfg.block_edges) || [];
    container.innerHTML = '';

    if (!blocks.length) {
      container.innerHTML = '<div class="empty"><strong>No blocks to draw</strong>'
        + 'The listing has no instructions yet.</div>';
      return;
    }

    const byLine = new Map(result.annotations.map((a) => [a.index, a]));
    const { placed, width, height } = buildLayout(blocks, edges);

    const svg = el('svg', {
      class: 'cfg', viewBox: `0 0 ${width} ${height}`,
      width, height, role: 'img', 'aria-label': 'Control flow graph',
    });

    const defs = el('defs');
    for (const [kind, colour] of Object.entries(EDGE_COLOUR)) {
      const marker = el('marker', {
        id: `arrow-${kind}`, viewBox: '0 0 10 10', refX: 9, refY: 5,
        markerWidth: 6, markerHeight: 6, orient: 'auto-start-reverse',
      });
      marker.appendChild(el('path', { d: 'M 0 0 L 10 5 L 0 10 z', fill: colour }));
      defs.appendChild(marker);
    }
    svg.appendChild(defs);

    // Edges first so nodes paint over them.
    for (const e of edges) {
      const a = placed.get(e.from);
      const b = e.to == null ? null : placed.get(e.to);
      if (!b) continue;
      const colour = EDGE_COLOUR[e.kind] || 'var(--text-faint)';
      svg.appendChild(el('path', {
        d: edgePath(a, b, e.kind, e.backward),
        fill: 'none', stroke: colour, 'stroke-width': e.backward ? 1.6 : 1.4,
        'stroke-dasharray': e.kind === 'fallthrough' ? '4 3' : (e.backward ? '6 3' : ''),
        'marker-end': `url(#arrow-${EDGE_COLOUR[e.kind] ? e.kind : 'fallthrough'})`,
        opacity: 0.85,
      }));
    }

    for (const b of blocks) {
      const pos = placed.get(b.id);
      const g = el('g', { class: 'cfg-node', 'data-block': b.id, tabindex: '0',
                          role: 'button', transform: `translate(${pos.x},${pos.y})` });

      g.appendChild(el('rect', {
        class: 'cfg-box' + (b.loop_header ? ' loop' : ''),
        width: pos.w, height: pos.h, rx: 7,
      }));

      const title = b.label ? `${b.label}:` : `block ${b.id}`;
      g.appendChild(el('text', { class: 'cfg-title', x: 11, y: 17 }, title));
      g.appendChild(el('text', { class: 'cfg-range', x: pos.w - 11, y: 17,
                                 'text-anchor': 'end' },
                      `${b.start}–${b.end}`));

      b.lines.slice(0, MAX_ROWS).forEach((lineNo, i) => {
        const ann = byLine.get(lineNo);
        if (!ann) return;
        const raw = ann.raw.trim().replace(/^[0-9a-f]+:\s*(?:[0-9a-f]{2}\s+)*/i, '');
        const text = raw.length > 34 ? raw.slice(0, 33) + '…' : raw;
        g.appendChild(el('text', {
          class: `cfg-ins cat-${ann.category}`, x: 11, y: PAD_Y + 10 + i * LINE_H,
        }, text));
      });
      if (b.lines.length > MAX_ROWS) {
        g.appendChild(el('text', {
          class: 'cfg-more', x: 11, y: PAD_Y + 10 + MAX_ROWS * LINE_H,
        }, `… ${b.lines.length - MAX_ROWS} more`));
      }

      const pick = () => onPick && onPick(b);
      g.addEventListener('click', pick);
      g.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); pick(); }
      });
      svg.appendChild(g);
    }

    const wrap = document.createElement('div');
    wrap.className = 'cfg-wrap';
    wrap.appendChild(svg);

    const legend = document.createElement('div');
    legend.className = 'cfg-legend';
    legend.innerHTML = [
      ['taken', 'branch taken'], ['fallthrough', 'falls through'],
      ['jump', 'unconditional'], ['indirect', 'indirect'],
    ].map(([k, label]) =>
      `<span><i style="background:${EDGE_COLOUR[k]}"></i>${label}</span>`).join('')
      + '<span><i class="dash"></i>back edge (loop)</span>';
    wrap.appendChild(legend);

    container.appendChild(wrap);
  }

  /* ---- stack frame -------------------------------------------------- */

  const ROLE_LABEL = {
    argument: 'argument', local: 'local', saved: 'saved', return: 'return address',
    outgoing: 'outgoing arg', scratch: 'scratch',
  };

  function renderFrame(container, result, onPick) {
    const frame = result.frame;
    container.innerHTML = '';

    if (!frame || !frame.slots.length) {
      container.innerHTML = '<div class="empty"><strong>No stack frame found</strong>'
        + 'This listing does not build one, or does not touch memory through '
        + 'EBP/RBP or ESP/RSP.</div>';
      return;
    }

    const isCil = frame.kind === 'cil';
    const head = document.createElement('div');
    head.className = 'frame-head';
    if (isCil) {
      head.innerHTML = `
        <div><span class="v">${frame.locals.length}</span><span class="k">${
          frame.locals.length === 1 ? 'local' : 'locals'}</span></div>
        <div><span class="v">${frame.maxstack == null ? '?' : frame.maxstack}</span><span class="k">declared maxstack</span></div>
        <div><span class="v">${frame.max_depth_seen}</span><span class="k">deepest stack seen</span></div>`;
    }
    if (!isCil) head.innerHTML = `
      <div><span class="v">${frame.word * 8}-bit</span><span class="k">word</span></div>
      <div><span class="v">${frame.reserved}</span><span class="k">${
        frame.reserved === 1 ? 'byte reserved' : 'bytes reserved'}</span></div>
      <div><span class="v">${frame.arguments.length}</span><span class="k">${
        frame.arguments.length === 1 ? 'argument' : 'arguments'}</span></div>
      <div><span class="v">${frame.locals.length}</span><span class="k">${
        frame.locals.length === 1 ? 'local' : 'locals'}</span></div>
      <div><span class="v">${frame.has_frame ? 'yes' : 'no'}</span><span class="k">frame pointer</span></div>`;
    container.appendChild(head);

    const note = document.createElement('p');
    note.className = 'frame-note';
    note.textContent = isCil
      ? 'Local variable slots from .locals init, with the lines that store to (w) and load from (r) each one.'
      : 'High addresses at the top. Arguments sit above the saved frame '
        + 'pointer; locals sit below it.';
    container.appendChild(note);

    const list = document.createElement('div');
    list.className = 'frame-list';

    let previous = null;
    for (const slot of frame.slots) {
      // Show a gap marker where the reserved region has unused space.
      if (previous && previous.base === slot.base && previous.base === 'frame') {
        const expected = previous.offset - previous.size;
        if (slot.offset < expected) {
          const gap = document.createElement('div');
          gap.className = 'frame-gap';
          gap.textContent = `${expected - slot.offset} bytes unused`;
          list.appendChild(gap);
        }
      }
      previous = slot;

      const sign = slot.offset >= 0 ? '+' : '−';
      const base = slot.base === 'frame' ? (frame.word === 8 ? 'RBP' : 'EBP')
                                         : (frame.word === 8 ? 'RSP' : 'ESP');
      const lines = [...slot.writes.map((n) => ['w', n]), ...slot.reads.map((n) => ['r', n])];
      const badges = lines.slice(0, 8).map(([kind, n]) =>
        `<button class="frame-ref ${kind}" data-line="${n}" title="${
          kind === 'w' ? 'written' : 'read'} on line ${n}">${kind}${n}</button>`).join('');

      const row = document.createElement('div');
      row.className = `frame-slot role-${slot.role}${slot.implied ? ' implied' : ''}`;
      row.innerHTML = `
        <span class="frame-addr">${slot.addr_label ? esc(slot.addr_label)
          : `[${base}${sign}${Math.abs(slot.offset)}]`}</span>
        <span class="frame-body">
          <span class="frame-name">${esc(slot.name)}</span>
          <span class="frame-detail">${esc(slot.detail || '')}</span>
        </span>
        <span class="frame-meta">
          <span class="frame-size">${slot.type_text ? esc(slot.type_text.replace(/^class\s+/, '')
            .replace(/\[[^\]]+\]/, '').split('.').pop()) : `${slot.size}B`}</span>
          <span class="frame-role">${esc(ROLE_LABEL[slot.role] || slot.role)}</span>
        </span>
        <span class="frame-refs">${badges}</span>`;
      list.appendChild(row);
    }

    list.addEventListener('click', (e) => {
      const ref = e.target.closest('[data-line]');
      if (ref && onPick) onPick(Number(ref.dataset.line));
    });
    container.appendChild(list);
  }

  window.AsmViews = { renderGraph, renderFrame };
})();

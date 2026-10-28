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

  /* ---- call graph (methods) ----------------------------------------- */

  const CG = { colW: 236, nodeH: 46, gapX: 64, gapY: 10, pad: 18, head: 34 };
  const LAYER_TITLE = { '-2': "callers' callers", '-1': 'called by', 0: 'this method',
                        1: 'calls', 2: 'which call' };
  const SEV_RANK = { warning: 0, notable: 1, info: 2 };
  const EDGE_STYLE = {
    call: { colour: 'var(--cat-data)', dash: '' },
    callvirt: { colour: 'var(--cat-data)', dash: '' },
    newobj: { colour: 'var(--cat-simd)', dash: '' },
    ldftn: { colour: 'var(--cat-arith)', dash: '5 4' },
    ldvirtftn: { colour: 'var(--cat-arith)', dash: '5 4' },
    jmp: { colour: 'var(--cat-control)', dash: '' },
  };
  const clip = (t, n) => (t.length > n ? t.slice(0, n - 1) + '…' : t);

  function renderCallGraph(container, graph, onPick) {
    container.innerHTML = '';
    if (!graph) {
      container.innerHTML = '<div class="empty"><strong>No call graph yet</strong>'
        + 'Open a method from a .NET assembly in the Methods tab to see who calls it and '
        + 'what it calls.</div>';
      return;
    }

    const layers = new Map();
    for (const n of graph.nodes) {
      if (!layers.has(n.layer)) layers.set(n.layer, []);
      layers.get(n.layer).push(n);
    }
    const order = [...layers.keys()].sort((a, b) => a - b);
    for (const k of order) {
      layers.get(k).sort((a, b) => (SEV_RANK[a.severity] ?? 3) - (SEV_RANK[b.severity] ?? 3)
        || a.label.localeCompare(b.label));
    }
    const rows = Math.max(...order.map((k) => layers.get(k).length));
    const width = CG.pad * 2 + order.length * CG.colW + (order.length - 1) * CG.gapX;
    const height = CG.pad * 2 + CG.head + rows * (CG.nodeH + CG.gapY) + 22;

    const pos = new Map();
    order.forEach((k, ci) => {
      const col = layers.get(k);
      const offset = ((rows - col.length) * (CG.nodeH + CG.gapY)) / 2;
      col.forEach((n, i) => pos.set(n.key, {
        x: CG.pad + ci * (CG.colW + CG.gapX),
        y: CG.pad + CG.head + offset + i * (CG.nodeH + CG.gapY), layer: k,
      }));
    });

    const wrap = document.createElement('div');
    wrap.className = 'cg-wrap';

    const head = document.createElement('div');
    head.className = 'cg-head';
    let crumbs = '';
    if (graph.path && graph.path.length) {
      crumbs = '<div class="cg-path">Reached from the entry point: ' + graph.path.map((p, i) =>
        (i === graph.path.length - 1 ? `<b>${esc(p.label)}</b>`
          : `<button class="link" data-method="${p.id}">${esc(p.label)}</button>`)).join(' › ')
        + '</div>';
    } else if (graph.reachability_known) {
      crumbs = '<div class="cg-path warnish">Not reached from the entry point or module '
        + 'initialiser by any direct call: it runs only if something reaches it indirectly.</div>';
    }
    const dropped = Object.values(graph.overflow || {}).reduce((a, b) => a + b, 0);
    head.innerHTML = `<div class="cg-title">${esc(graph.label)}</div>${crumbs}`
      + (dropped ? `<div class="cg-note">${dropped} less relevant neighbour${dropped === 1 ? '' : 's'} `
        + 'not shown; flagged methods are kept first.</div>' : '');
    wrap.appendChild(head);

    if (graph.nodes.length === 1) {
      const empty = document.createElement('div');
      empty.className = 'empty';
      empty.innerHTML = '<strong>No calls in or out</strong>Nothing in this assembly calls this '
        + 'method directly, and it calls nothing.';
      wrap.appendChild(empty);
      container.appendChild(wrap);
      return;
    }

    const svg = el('svg', { class: 'cg', viewBox: `0 0 ${width} ${height}`, width, height,
                            role: 'img', 'aria-label': 'Call graph' });
    const defs = el('defs');
    for (const [kind, st] of Object.entries(EDGE_STYLE)) {
      const marker = el('marker', { id: `cg-${kind}`, viewBox: '0 0 10 10', refX: 9, refY: 5,
                                    markerWidth: 6, markerHeight: 6, orient: 'auto-start-reverse' });
      marker.appendChild(el('path', { d: 'M 0 0 L 10 5 L 0 10 z', fill: st.colour }));
      defs.appendChild(marker);
    }
    svg.appendChild(defs);

    order.forEach((k) => {
      const x = pos.get(layers.get(k)[0].key).x;
      svg.appendChild(el('text', { class: 'cg-col', x: x + CG.colW / 2, y: CG.pad + 12,
                                   'text-anchor': 'middle' }, LAYER_TITLE[k] || ''));
      const more = (graph.overflow || {})[String(k)];
      if (more) {
        const last = layers.get(k).at(-1);
        svg.appendChild(el('text', { class: 'cg-more', x: x + CG.colW / 2,
                                     y: pos.get(last.key).y + CG.nodeH + 16, 'text-anchor': 'middle' },
                           `+${more} more`));
      }
    });

    for (const e of graph.edges) {
      const a = pos.get(e.from), b = pos.get(e.to);
      if (!a || !b) continue;
      const st = EDGE_STYLE[e.kind] || EDGE_STYLE.call;
      let d;
      if (a.layer < b.layer) {
        const x1 = a.x + CG.colW, y1 = a.y + CG.nodeH / 2, x2 = b.x, y2 = b.y + CG.nodeH / 2;
        const mid = (x1 + x2) / 2;
        d = `M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}`;
      } else {
        // Recursion or a call back to the left: arc over the top.
        const x1 = a.x + CG.colW / 2, y1 = a.y, x2 = b.x + CG.colW / 2, y2 = b.y;
        const top = Math.min(y1, y2) - 26;
        d = `M ${x1} ${y1} C ${x1} ${top}, ${x2} ${top}, ${x2} ${y2}`;
      }
      const path = el('path', { d, fill: 'none', stroke: st.colour, 'stroke-width': 1.3 + Math.min(2, e.count / 4),
                                'stroke-dasharray': st.dash, opacity: 0.8,
                                'marker-end': `url(#cg-${EDGE_STYLE[e.kind] ? e.kind : 'call'})` });
      path.appendChild(el('title', {}, `${e.kind}${e.count > 1 ? ` ×${e.count}` : ''}`));
      svg.appendChild(path);
    }

    for (const n of graph.nodes) {
      const p = pos.get(n.key);
      const g = el('g', { class: `cg-node ${n.kind}${n.key === graph.focus ? ' focus' : ''}`,
                          transform: `translate(${p.x},${p.y})` });
      if (n.kind === 'method' && n.key !== graph.focus) {
        g.setAttribute('tabindex', '0');
        g.setAttribute('role', 'button');
      }
      g.appendChild(el('rect', { class: 'cg-box', width: CG.colW, height: CG.nodeH, rx: 7 }));
      g.appendChild(el('rect', { class: `cg-sev sev-${n.severity || 'none'}`, width: 4,
                                 height: CG.nodeH - 10, x: 0, y: 5, rx: 2 }));
      g.appendChild(el('text', { class: 'cg-label', x: 12, y: 19 }, clip(n.label, 30)));
      let sub = n.kind === 'external' ? n.detail.split('::')[0] : (n.findings.length
        ? n.findings.slice(0, 2).join(', ') : (n.pinvoke ? 'P/Invoke' : `${n.callers} caller${n.callers === 1 ? '' : 's'}, ${n.callees} callee${n.callees === 1 ? '' : 's'}`));
      if (n.kind === 'external' && n.findings.length) sub = n.findings.slice(0, 2).join(', ');
      g.appendChild(el('text', { class: 'cg-sub', x: 12, y: 35 }, clip(sub, 36)));
      g.appendChild(el('title', {}, `${n.detail}${n.findings.length ? '\n' + n.findings.join(', ') : ''}`));
      if (n.kind === 'method' && n.key !== graph.focus && onPick) {
        const pick = () => onPick(n.id);
        g.addEventListener('click', pick);
        g.addEventListener('keydown', (ev) => {
          if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); pick(); }
        });
      }
      svg.appendChild(g);
    }

    const scroller = document.createElement('div');
    scroller.className = 'cg-scroll';
    scroller.appendChild(svg);
    wrap.appendChild(scroller);

    const legend = document.createElement('div');
    legend.className = 'cfg-legend';
    legend.innerHTML = '<span><i style="background:var(--cat-data)"></i>call</span>'
      + '<span><i style="background:var(--cat-simd)"></i>constructor</span>'
      + '<span><i class="dash" style="background:repeating-linear-gradient(90deg,var(--cat-arith) 0 5px,transparent 5px 8px)"></i>delegate target</span>'
      + '<span>callvirt edges point at the declared method; overrides are not followed</span>';
    wrap.appendChild(legend);

    wrap.addEventListener('click', (ev) => {
      const link = ev.target.closest('[data-method]');
      if (link && onPick) onPick(Number(link.dataset.method));
    });
    container.appendChild(wrap);
  }

  window.AsmViews = { renderGraph, renderFrame, renderCallGraph };
})();

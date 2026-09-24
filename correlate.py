"""Module 4: identity correlation and attribution.

Builds a graph linking the artefacts of a message - sender address, sending
domain, reply-to, look-alike domains, origin IP, hop IPs, wallets - so shared
infrastructure across MULTIPLE emails becomes visible. Two different phishing
mails that resolve to the same origin IP are attributable to one campaign.

On top of that literal, indicator-based graph, ``add_semantic_edges`` can
overlay a second kind of link: cases whose origin an AI similarity search
(e.g. nomic_embed.find_similar_origins) considers alike, even when they
share no raw indicator at all. Those are drawn as dashed lines so a reader
can tell "hard evidence" from "AI-inferred hypothesis" at a glance.

For campaigns bigger than a handful of cases, ``build_graph(..., max_cases=N)``
takes a random sample so the picture stays legible instead of turning into a
hairball; the sample is reproducible only if you pass a ``seed``, otherwise
every call reshuffles.

graph_figure() renders a dark, glowing "SOC evidence board" look - halo'd
nodes, curved gradient-toned edges, and (when a node is highlighted) a
clean hub-and-spoke ring around it - to match the rest of the dark
dashboard theme instead of standing out as a flat, plain chart.

networkx holds the graph; plotly draws it (no graphviz / system deps).

Standalone:  python correlate.py
"""
import math
import random

import networkx as nx
import plotly.graph_objects as go

# --------------------------------------------------------------------------
# Visual language
# --------------------------------------------------------------------------
# One glowing color/shape per artefact type, tuned for the dark canvas
# graph_figure() renders on. "case" is the hub - biggest, brightest, a star
# so it reads as the center of gravity even before you look at the edges.
NODE_STYLE = {
    "email":    {"color": "#38bdf8", "size": 22, "symbol": "circle"},
    "domain":   {"color": "#e879f9", "size": 20, "symbol": "diamond"},
    "ip":       {"color": "#f87171", "size": 21, "symbol": "square"},
    "infra":    {"color": "#fb923c", "size": 20, "symbol": "x"},
    "wallet":   {"color": "#34d399", "size": 18, "symbol": "triangle-up"},
    "case":     {"color": "#fb7185", "size": 34, "symbol": "star"},
    # Historical/AI-matched origin - not one of the raw indicators on any
    # analyzed case, only surfaced via semantic similarity (see
    # add_semantic_edges). Purple ties it visually to "AI/ML-inferred".
    "semantic": {"color": "#a78bfa", "size": 17, "symbol": "hexagon"},
}

# One color/dash style per relationship, so edges aren't just "some gray
# lines" - the color and dash pattern alone tell you what kind of link it
# is, and it doubles as the plot legend. Solid = literal/observed evidence.
# Dashed/dotted = inferred (a routing hop, an infra tag, an AI similarity
# match) rather than a directly-extracted artefact.
REL_STYLE = {
    "sent by":         {"color": "#38bdf8", "dash": "solid",   "width": 2.0},
    "at domain":       {"color": "#e879f9", "dash": "solid",   "width": 1.8},
    "replies to":      {"color": "#fbbf24", "dash": "solid",   "width": 2.0},
    "links to":        {"color": "#34d399", "dash": "solid",   "width": 1.6},
    "originated at":   {"color": "#f87171", "dash": "solid",   "width": 2.4},
    "relayed via":     {"color": "#fb923c", "dash": "dash",    "width": 1.6},
    "pay to":          {"color": "#4ade80", "dash": "solid",   "width": 1.8},
    "is":              {"color": "#94a3b8", "dash": "dot",     "width": 1.3},
    "matches":         {"color": "#fb7185", "dash": "dot",     "width": 1.8},
    "semantic match":  {"color": "#a78bfa", "dash": "dashdot", "width": 1.6},
}
_REL_FALLBACK = {"color": "#94a3b8", "dash": "solid", "width": 1.3}
_REL_ORDER = list(REL_STYLE.keys())

# Dark navy "evidence board" canvas - deliberately not pure black (flat and
# lifeless) and not the app's default transparent-on-dark (which is what
# made the old chart look like nothing at all) - a real, deep, slightly
# blue-toned background the glowing nodes/edges can pop against.
_CANVAS = {
    "paper": "#0b1526",
    "plot": "#0b1526",
    "text": "#e2e8f0",
    "muted": "#94a3b8",
}


def _norm(value):
    return str(value).strip().lower() if value is not None else ""


def _sample_cases(cases, max_cases, seed):
    """Filter out error rows, then (if needed) take a random subset.

    Returns (cases_to_use, total_valid_count, was_sampled). Sampling only
    kicks in when max_cases is set and there are actually more cases than
    that - small case sets are always used in full.
    """
    valid = [c for c in cases if isinstance(c, dict) and "error" not in c]
    if not max_cases or len(valid) <= max_cases:
        return valid, len(valid), False
    rng = random.Random(seed)
    return rng.sample(valid, max_cases), len(valid), True


def build_graph(cases, max_cases=None, seed=None):
    """Build a normalized case/indicator graph for correlation and attribution.

    Node IDs are namespaced by artifact type so an email, domain, IP, or wallet
    can never collide accidentally. Case IDs use the evidence hash when one is
    available, which keeps repeated filenames/CSV row names separate.

    max_cases: if set and there are more valid cases than this, a random
        sample of this size is used instead - keeps large campaigns (e.g. a
        CSV of hundreds of rows) legible rather than a hairball. Pass `seed`
        for a reproducible sample across reruns; leave it None for a fresh
        shuffle every call. Sampling metadata is recorded on G.graph
        ("case_count", "total_case_count", "sampled") so a caller can show
        "20 of 143 cases" without having to redo the filtering itself.
    """
    cases, total, was_sampled = _sample_cases(cases, max_cases, seed)

    G = nx.DiGraph()
    G.graph["case_count"] = len(cases)
    G.graph["total_case_count"] = total
    G.graph["sampled"] = was_sampled

    def add(node_id, kind, label=None, **attrs):
        if not node_id:
            return None
        if node_id not in G:
            G.add_node(node_id, kind=kind, label=label or node_id, **attrs)
        else:
            # Fill in metadata discovered from later cases without changing
            # the canonical label/type.
            for key, value in attrs.items():
                if value not in (None, "", []) and not G.nodes[node_id].get(key):
                    G.nodes[node_id][key] = value
        return node_id

    for case in cases:
        parsed = case.get("parsed", {}) or {}
        iocs = case.get("iocs", {}) or {}
        geo = case.get("geo", {}) or {}
        headers = case.get("headers", {}) or {}

        evidence_key = _norm(case.get("_evidence_hash") or case.get("name") or "?")
        case_id = "case:{}".format(evidence_key)
        add(
            case_id,
            "case",
            case.get("name", "?"),
            verdict=case.get("level", ""),
            score=case.get("score", 0),
        )

        sender = _norm(parsed.get("from_addr"))
        if sender:
            sender_id = "email:" + sender
            add(sender_id, "email", sender)
            G.add_edge(case_id, sender_id, rel="sent by")

        from_domain = _norm(parsed.get("from_domain"))
        if from_domain:
            domain_id = "domain:" + from_domain
            add(domain_id, "domain", from_domain)
            if sender:
                G.add_edge("email:" + sender, domain_id, rel="at domain")

        reply_to = _norm(parsed.get("reply_to"))
        if reply_to and reply_to != sender:
            reply_id = "email:" + reply_to
            add(reply_id, "email", reply_to)
            G.add_edge(case_id, reply_id, rel="replies to")
            reply_domain = _norm(parsed.get("reply_to_domain"))
            if reply_domain:
                reply_domain_id = "domain:" + reply_domain
                add(reply_domain_id, "domain", reply_domain)
                G.add_edge(reply_id, reply_domain_id, rel="at domain")

        domains = iocs.get("domains", []) or []
        for domain in domains[:10]:
            domain = _norm(domain)
            if not domain:
                continue
            domain_id = "domain:" + domain
            add(domain_id, "domain", domain)
            G.add_edge(case_id, domain_id, rel="links to")

        origin_record = geo.get("origin") or {}
        origin = _norm(origin_record.get("ip"))
        if origin:
            ip_id = "ip:" + origin
            add(
                ip_id,
                "ip",
                origin,
                country=origin_record.get("country", ""),
                isp=origin_record.get("isp", ""),
            )
            G.add_edge(case_id, ip_id, rel="originated at")

            infra = _norm(origin_record.get("infra"))
            if infra and infra not in ("corporate", "residential", "unknown"):
                infra_id = "infra:" + infra
                add(infra_id, "infra", origin_record.get("infra_label", infra))
                G.add_edge(ip_id, infra_id, rel="is")

        for hop in (geo.get("hops", []) or [])[1:5]:
            hop_ip = _norm(hop.get("ip"))
            if not hop_ip:
                continue
            hop_id = "ip:" + hop_ip
            add(
                hop_id,
                "ip",
                hop_ip,
                country=hop.get("country", ""),
                isp=hop.get("isp", ""),
            )
            G.add_edge(case_id, hop_id, rel="relayed via")

        for wallet in (iocs.get("wallets", []) or [])[:5]:
            wallet = _norm(wallet)
            if not wallet:
                continue
            wallet_id = "wallet:" + wallet
            add(wallet_id, "wallet", wallet[:14] + "...")
            G.add_edge(case_id, wallet_id, rel="pay to")

        if headers.get("bec", {}).get("is_bec"):
            add("infra:bec", "infra", "BEC campaign")
            G.add_edge(case_id, "infra:bec", rel="matches")

    return G


def add_semantic_edges(G, cases, similar_fn, min_similarity=0.72, top_k=3):
    """Overlay dashed "semantic match" edges from an AI origin-similarity
    search (e.g. nomic_embed.find_similar_origins) on top of the literal
    indicator graph build_graph() already produced.

    similar_fn(evidence_hash, top_k=top_k) must return an iterable of dicts
    shaped like nomic_embed.find_similar_origins already returns - at least
    "similarity" (0-1 float) and "ip" (str). Any case with no indexed
    embedding yet, or any failure calling similar_fn at all, is silently
    skipped per-case so an unavailable/slow AI backend can never break the
    graph - worst case, you just don't get the extra dashed lines this time.

    Mutates and returns G. A match whose IP isn't already a node in G is
    added as a small "semantic" node (a case elsewhere in your history that
    resembles this one, even though it shares no raw indicator with any
    case currently on screen) rather than being dropped.
    """
    if not similar_fn or G.number_of_nodes() == 0:
        return G

    for case in cases:
        if not isinstance(case, dict) or "error" in case:
            continue
        case_hash = case.get("_evidence_hash")
        if not case_hash:
            continue
        case_id = "case:" + _norm(case_hash)
        if case_id not in G:
            continue

        own_ip = _norm(((case.get("geo", {}) or {}).get("origin", {}) or {}).get("ip"))

        try:
            matches = similar_fn(case_hash, top_k=top_k) or []
        except Exception:
            continue

        for match in matches:
            try:
                similarity = float(match.get("similarity", 0))
            except (TypeError, ValueError, AttributeError):
                continue
            if similarity < min_similarity:
                continue
            match_ip = _norm(match.get("ip"))
            if not match_ip or match_ip == own_ip:
                continue  # not interesting: itself, or no usable IP on the match

            node_id = "ip:" + match_ip
            if node_id not in G:
                G.add_node(
                    node_id, kind="semantic", label=match_ip,
                    country=match.get("country", ""),
                    infra=match.get("infra_label", ""),
                )
            if G.has_edge(case_id, node_id) and G.edges[case_id, node_id].get("rel") != "semantic match":
                continue  # already linked by a literal indicator - don't overwrite that edge
            existing = G.edges.get((case_id, node_id))
            if not existing or similarity > existing.get("similarity", 0):
                G.add_edge(case_id, node_id, rel="semantic match", similarity=similarity)

    return G


def shared_indicators(G):
    """Artefacts touched by more than one case - the attribution payoff.

    Each record also reports whether the sharing is purely semantic (every
    connecting edge is an AI-inferred "semantic match" rather than a
    literal, extracted indicator) so a caller can badge it differently -
    e.g. "🔗 shared indicator" vs "🧠 AI-inferred".
    """
    shared = []
    for node, data in G.nodes(data=True):
        if data.get("kind") == "case":
            continue
        case_edges = [
            (n, G.edges[n, node].get("rel"))
            for n in G.predecessors(node)
            if G.nodes[n].get("kind") == "case"
        ]
        if len(case_edges) > 1:
            shared.append({
                "indicator": data.get("label", node),
                "kind": data.get("kind"),
                "cases": [G.nodes[c].get("label", c) for c, _ in case_edges],
                "semantic": all(rel == "semantic match" for _, rel in case_edges),
            })
    shared.sort(key=lambda s: len(s["cases"]), reverse=True)
    return shared


def _curve(x0, y0, x1, y1, bend=0.15, n=16):
    """Points along a gentle quadratic-bezier arc from (x0,y0) to (x1,y1)
    instead of a straight segment - this is most of what makes the graph
    read as a lively "signal map" instead of a plain node-link diagram."""
    dx, dy = x1 - x0, y1 - y0
    length = math.hypot(dx, dy) or 1e-6
    px, py = -dy / length, dx / length
    mx, my = (x0 + x1) / 2, (y0 + y1) / 2
    cx, cy = mx + px * length * bend, my + py * length * bend
    xs, ys = [], []
    for i in range(n):
        t = i / (n - 1)
        xs.append((1 - t) ** 2 * x0 + 2 * (1 - t) * t * cx + t ** 2 * x1)
        ys.append((1 - t) ** 2 * y0 + 2 * (1 - t) * t * cy + t ** 2 * y1)
    return xs, ys


def _typical_edge_length(pos, G):
    """Median length of G's edges in `pos`, used as a stable "one hop should
    look about this long" ruler. Cheaper/steadier than the layout's overall
    bounding-box spread, which balloons once clustering spreads unrelated
    cases far apart and would otherwise make rings/curves scale to the size
    of the whole canvas instead of the size of a typical connection."""
    lens = []
    for u, v in G.edges():
        if u in pos and v in pos:
            (x0, y0), (x1, y1) = pos[u], pos[v]
            lens.append(math.hypot(x1 - x0, y1 - y0))
    if not lens:
        return 1.0
    lens.sort()
    return lens[len(lens) // 2] or 1.0


def _radial_ring(pos, G, center):
    """Re-place `center` at the middle of a clean circle of its direct
    neighbors, radius scaled to a typical edge length (not the whole
    canvas) - turns the highlighted node into a proper hub-and-spoke focal
    point (like a radar ping) instead of wherever the layout dropped it,
    and stays a sane size no matter how many other clusters are on screen."""
    radius = _typical_edge_length(pos, G) * 1.7
    cx, cy = pos[center]
    neighbors = sorted(set(G.predecessors(center)) | set(G.successors(center)))
    n = len(neighbors)
    for i, node in enumerate(neighbors):
        angle = (2 * math.pi * i / n) - math.pi / 2 if n else 0
        pos[node] = (cx + radius * math.cos(angle), cy + radius * math.sin(angle))
    pos[center] = (cx, cy)


def _clustered_layout(G, seed=42):
    """Lay G out one connected "case cluster" at a time instead of forcing
    the whole graph through a single global layout.

    The old code ran kamada_kawai_layout() (falling back to spring, then
    circular) on the *entire* graph at once. For a correlation graph that's
    a set of many small case-centric stars with only a few cross-links
    between them, that combination is a known pathology: cases that share
    no indicator have nothing pulling them together, so the solver's
    stress-minimization spreads them into one big ring with every case and
    every one of its indicators sitting on that same circle - then every
    edge, including the handful of genuinely meaningful cross-case links,
    has to cut straight across the middle to reach its target. That's the
    "hairball" look: dozens of chords all crossing near the center, with
    no visual difference between "this case's own IP" and "this shared
    indicator links two different campaigns."

    Here, each weakly-connected component (in practice: one case plus its
    own indicators, or several cases that a shared indicator has merged
    together) gets its own compact local layout, sized to its node count.
    Those clusters are then packed onto a plain grid with a fixed margin
    between cells, so:
      - a case's own indicators always stay visually next to it,
      - unrelated cases never overlap or get tangled with each other, and
      - the only edges that still have to travel any distance are the
        real cross-case correlations - exactly the signal this graph
        exists to surface, and now the only thing drawing attention to
        itself instead of being buried in noise.

    Falls back to a single-cluster layout (equivalent to the old behavior)
    when the whole graph is one component, so small/simple graphs look the
    same as before.
    """
    undirected = G.to_undirected()
    components = list(nx.connected_components(undirected))
    components.sort(key=len, reverse=True)

    n_comp = len(components)
    cols = max(1, math.ceil(math.sqrt(n_comp)))
    rows = max(1, math.ceil(n_comp / cols))

    local_layouts, radii = [], []
    for comp in components:
        sub = undirected.subgraph(comp)
        if len(comp) == 1:
            local_layouts.append({next(iter(comp)): (0.0, 0.0)})
            radii.append(0.4)
            continue
        try:
            local_pos = nx.kamada_kawai_layout(sub)
        except Exception:
            try:
                local_pos = nx.spring_layout(
                    sub, seed=seed, k=1.2 / math.sqrt(len(comp)), iterations=150
                )
            except Exception:
                local_pos = nx.circular_layout(sub)
        xs = [p[0] for p in local_pos.values()]
        ys = [p[1] for p in local_pos.values()]
        spread = max(max(xs) - min(xs), max(ys) - min(ys), 1e-6)
        # Bigger clusters get proportionally more room so a 15-node hub
        # doesn't get squeezed as tight as a lone case-and-its-IP pair.
        target_spread = 0.6 * math.sqrt(len(comp))
        scale = target_spread / spread
        local_layouts.append({n: (x * scale, y * scale) for n, (x, y) in local_pos.items()})
        radii.append(target_spread * 0.5 + 0.3)

    # One uniform cell size (based on the largest cluster) keeps the grid
    # even and guarantees no two clusters can overlap, regardless of how
    # lopsided the campaign sizes are.
    cell = max(radii) * 2.5 if radii else 1.8
    cell = max(cell, 1.8)

    pos = {}
    for idx, local_pos in enumerate(local_layouts):
        row, col = divmod(idx, cols)
        cx = (col - (cols - 1) / 2) * cell
        cy = (row - (rows - 1) / 2) * cell
        for node, (x, y) in local_pos.items():
            pos[node] = (cx + x, cy + y)
    return pos


def graph_figure(G, height=520, highlight_node=None):
    """Plotly node-link diagram of the correlation graph.

    A dark, glowing "evidence board" look to match the rest of the SOC
    dashboard: halo'd nodes, curved color-and-dash-coded edges (doubling as
    the legend - solid = literal shared indicator, dashed/dotted = inferred),
    node size scaled a little by connection count so hubs stand out, and
    labels shown only for cases and nodes with 2+ connections so the picture
    doesn't drown in single-use indicator labels - hover still shows full
    detail for every node and every edge.

    highlight_node: an "email:...", "domain:...", "ip:...", "case:...", etc.
    node id (matches what customdata carries per point, for click-driven
    highlighting from the caller). When set, that node and its direct
    neighbors are pulled into a clean radial ring and lit up at full
    brightness; everything else fades instead of disappearing, so context
    is kept.
    """
    if G.number_of_nodes() == 0:
        fig = go.Figure()
        fig.add_annotation(
            text="No indicators to correlate yet", showarrow=False,
            font=dict(size=14, color=_CANVAS["muted"]),
        )
        fig.update_layout(
            height=height, paper_bgcolor=_CANVAS["paper"], plot_bgcolor=_CANVAS["plot"],
            xaxis=dict(visible=False), yaxis=dict(visible=False),
        )
        return fig

    pos = _clustered_layout(G)
    typical_len = _typical_edge_length(pos, G)

    # Fan each node's label outward from its own cluster's centroid instead
    # of pinning every label to "bottom center" - with clusters now packed
    # close together, stacking every label on the same side is what would
    # keep them overlapping even after the layout fix.
    _label_dirs = [
        "middle right", "top right", "top center", "top left",
        "middle left", "bottom left", "bottom center", "bottom right",
    ]
    _centroids = {}
    for comp in nx.connected_components(G.to_undirected()):
        cxv = sum(pos[n][0] for n in comp) / len(comp)
        cyv = sum(pos[n][1] for n in comp) / len(comp)
        for n in comp:
            _centroids[n] = (cxv, cyv)

    def _label_position(node):
        cx, cy = _centroids.get(node, pos[node])
        x, y = pos[node]
        dx, dy = x - cx, y - cy
        if abs(dx) < 1e-6 and abs(dy) < 1e-6:
            return "bottom center"
        angle = math.degrees(math.atan2(dy, dx))
        return _label_dirs[round(angle / 45) % 8]

    highlight_set = set()
    if highlight_node and highlight_node in G:
        highlight_set = (
            {highlight_node}
            | set(G.predecessors(highlight_node))
            | set(G.successors(highlight_node))
        )
        _radial_ring(pos, G, highlight_node)

    fig = go.Figure()

    # -- faint ambient color bleed in the corners, purely atmospheric ------
    xs_all = [p[0] for p in pos.values()]
    ys_all = [p[1] for p in pos.values()]
    if xs_all and ys_all:
        fig.add_trace(go.Scatter(
            x=[max(xs_all)], y=[max(ys_all)], mode="markers", showlegend=False, hoverinfo="skip",
            marker=dict(size=280, color="#38bdf8", opacity=0.05),
        ))
        fig.add_trace(go.Scatter(
            x=[min(xs_all)], y=[min(ys_all)], mode="markers", showlegend=False, hoverinfo="skip",
            marker=dict(size=280, color="#fb7185", opacity=0.05),
        ))

    # -- one curve precomputed per edge, shared by its styled line and its
    # hover hit-marker so the two always line up -------------------------
    edge_curves = {}
    for idx, (u, v, data) in enumerate(G.edges(data=True)):
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        # Short, within-a-cluster edges keep the lively 0.15 bend that gives
        # the graph its "signal map" feel. Long edges - almost always a
        # cross-case correlation now that clustering keeps everything else
        # local - taper toward straight instead of swooping across the
        # whole canvas, so they read as a clean, deliberate link rather
        # than another strand in a tangle.
        length = math.hypot(x1 - x0, y1 - y0)
        ratio = (length / typical_len) if typical_len else 1.0
        magnitude = 0.15 if ratio <= 1.6 else max(0.035, 0.15 * (1.6 / ratio))
        bend = magnitude if idx % 2 == 0 else -magnitude
        edge_curves[(u, v)] = (_curve(x0, y0, x1, y1, bend=bend), data)

    edges_by_rel = {}
    for u, v, data in G.edges(data=True):
        edges_by_rel.setdefault(data.get("rel", "related"), []).append((u, v, data))

    def _edge_trace(edges, style, opacity, showlegend, name, glow=False):
        xs, ys = [], []
        for u, v, _ in edges:
            (cxs, cys), _data = edge_curves[(u, v)]
            xs += cxs + [None]
            ys += cys + [None]
        return go.Scatter(
            x=xs, y=ys, mode="lines", hoverinfo="skip", showlegend=showlegend, name=name,
            line=dict(width=style["width"] * (4.2 if glow else 1.0), color=style["color"],
                       dash="solid" if glow else style["dash"]),
            opacity=opacity,
        )

    for rel in sorted(edges_by_rel, key=lambda r: _REL_ORDER.index(r) if r in _REL_ORDER else len(_REL_ORDER)):
        style = REL_STYLE.get(rel, _REL_FALLBACK)
        edge_list = edges_by_rel[rel]
        legend_name = rel.replace("_", " ").title()
        if highlight_set:
            touching = [e for e in edge_list if e[0] in highlight_set and e[1] in highlight_set]
            other = [e for e in edge_list if e not in touching]
        else:
            touching, other = edge_list, []
        if touching:
            fig.add_trace(_edge_trace(touching, style, 0.16, False, legend_name, glow=True))
            fig.add_trace(_edge_trace(touching, style, 0.95, True, legend_name))
        if other:
            fig.add_trace(_edge_trace(other, style, 0.05, False, legend_name))

    # Invisible wide-hit-area markers at each edge's curve midpoint so
    # hovering an edge explains the relationship, not just the endpoints.
    if edge_curves:
        mid_x, mid_y, mid_text = [], [], []
        for (u, v), ((cxs, cys), data) in edge_curves.items():
            mid_i = len(cxs) // 2
            mid_x.append(cxs[mid_i])
            mid_y.append(cys[mid_i])
            rel = data.get("rel", "related")
            extra = f"<br>similarity: {data['similarity']:.0%}" if data.get("similarity") is not None else ""
            mid_text.append(
                "<b>{}</b> \u2192 <b>{}</b><br><i>{}</i>{}".format(
                    G.nodes[u].get("label", u), G.nodes[v].get("label", v), rel, extra
                )
            )
        fig.add_trace(go.Scatter(
            x=mid_x, y=mid_y, mode="markers", showlegend=False,
            marker=dict(size=16, color="rgba(0,0,0,0)"),
            hovertext=mid_text, hoverinfo="text",
        ))

    # -- nodes, grouped by kind, each with a soft glow halo underneath ----
    degree = dict(G.degree())
    for kind, style in NODE_STYLE.items():
        nodes = [n for n, d in G.nodes(data=True) if d.get("kind") == kind]
        if not nodes:
            continue
        hover, text, sizes, opacities, textpositions = [], [], [], [], []
        for node in nodes:
            data = G.nodes[node]
            deg = degree.get(node, 0)
            bits = ["<b>{}</b>".format(data.get("label", node)), "type: {}".format(kind)]
            for key in ("country", "isp", "verdict", "infra"):
                if data.get(key):
                    bits.append("{}: {}".format(key, data[key]))
            bits.append("connections: {}".format(deg))
            hover.append("<br>".join(bits))
            text.append(data.get("label", node) if (kind == "case" or deg >= 2) else "")
            textpositions.append(_label_position(node))
            size = style["size"] + min(deg, 6) * 1.3 + (12 if node == highlight_node else 0)
            sizes.append(size)
            if highlight_set:
                opacities.append(1.0 if node in highlight_set else 0.12)
            else:
                opacities.append(0.95)

        xs = [pos[n][0] for n in nodes]
        ys = [pos[n][1] for n in nodes]
        fig.add_trace(go.Scatter(
            x=xs, y=ys, mode="markers", showlegend=False, hoverinfo="skip",
            marker=dict(size=[s * 2.3 for s in sizes], color=style["color"],
                        opacity=[min(o * 0.32, 0.26) for o in opacities], line=dict(width=0)),
        ))
        fig.add_trace(go.Scatter(
            x=xs, y=ys, mode="markers+text", name=kind.capitalize(),
            text=text, textposition=textpositions,
            textfont=dict(size=9, color=_CANVAS["text"]),
            hovertext=hover, hoverinfo="text", customdata=nodes,
            marker=dict(
                size=sizes, color=style["color"], symbol=style["symbol"],
                opacity=opacities, line=dict(width=1.4, color="#0b1526"),
            ),
        ))

    fig.update_layout(
        height=height, showlegend=True,
        legend=dict(
            orientation="h", yanchor="bottom", y=1.01,
            font=dict(color=_CANVAS["text"], size=11),
            bgcolor="rgba(15,23,42,0.85)",
        ),
        margin=dict(l=10, r=10, t=30, b=10),
        xaxis=dict(visible=False, showgrid=False, zeroline=False),
        yaxis=dict(visible=False, showgrid=False, zeroline=False, scaleanchor="x", scaleratio=1),
        paper_bgcolor=_CANVAS["paper"],
        plot_bgcolor=_CANVAS["plot"],
        font=dict(family="Inter, Segoe UI, Arial, sans-serif", color=_CANVAS["text"]),
        hoverlabel=dict(bgcolor="#0f172a", bordercolor="#334155", font=dict(color=_CANVAS["text"])),
        dragmode="pan",
    )
    return fig


if __name__ == "__main__":
    demo_cases = [
        {
            "name": "demo-1", "level": "Critical", "score": 91,
            "_evidence_hash": "hash1",
            "parsed": {"from_addr": "a@evil.com", "from_domain": "evil.com",
                       "reply_to": "b@ru-drop.ru", "reply_to_domain": "ru-drop.ru"},
            "iocs": {"domains": ["bit.ly"], "wallets": []},
            "geo": {"origin": {"ip": "185.220.101.45", "infra": "tor",
                               "infra_label": "Tor exit node", "country": "Germany"},
                    "hops": []},
            "headers": {"bec": {"is_bec": False}},
        },
        {
            "name": "demo-2", "level": "High", "score": 74,
            "_evidence_hash": "hash2",
            "parsed": {"from_addr": "c@fake-bank.com", "from_domain": "fake-bank.com",
                       "reply_to": None, "reply_to_domain": None},
            "iocs": {"domains": ["bit.ly"], "wallets": ["1A2b3C4d5E6f7G8h9I0j"]},
            "geo": {"origin": {"ip": "185.220.101.45", "infra": "tor",
                               "infra_label": "Tor exit node", "country": "Germany"},
                    "hops": [{"ip": "10.0.0.1", "country": "NL", "isp": "Relay"}]},
            "headers": {"bec": {"is_bec": False}},
        },
    ]

    def _fake_similar_fn(evidence_hash, top_k=3):
        if evidence_hash == "hash1":
            return [{"similarity": 0.81, "ip": "91.219.237.244",
                      "country": "Russia", "infra_label": "Bulletproof host"}]
        return []

    G = build_graph(demo_cases, max_cases=20, seed=1)
    add_semantic_edges(G, demo_cases, _fake_similar_fn)
    print("sampled:", G.graph)
    print("nodes:", G.number_of_nodes(), " edges:", G.number_of_edges())
    print("shared:", shared_indicators(G))
    fig = graph_figure(G, highlight_node="case:hash1")
    print("figure built:", type(fig).__name__, "traces:", len(fig.data))
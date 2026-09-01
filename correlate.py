"""Module 4: identity correlation and attribution.

Builds a graph linking the artefacts of a message - sender address, sending
domain, reply-to, look-alike domains, origin IP, hop IPs, wallets - so shared
infrastructure across MULTIPLE emails becomes visible. Two different phishing
mails that resolve to the same origin IP are attributable to one campaign.

networkx holds the graph; plotly draws it (no graphviz / system deps).

Standalone:  python correlate.py
"""
import networkx as nx
import plotly.graph_objects as go

NODE_STYLE = {
    "email":  {"color": "#1565c0", "size": 20, "symbol": "circle"},
    "domain": {"color": "#6a1b9a", "size": 17, "symbol": "diamond"},
    "ip":     {"color": "#e65100", "size": 19, "symbol": "square"},
    "infra":  {"color": "#b71c1c", "size": 22, "symbol": "x"},
    "wallet": {"color": "#00695c", "size": 16, "symbol": "triangle-up"},
    "case":   {"color": "#37474f", "size": 26, "symbol": "star"},
}


def build_graph(cases):
    """cases: list of {name, parsed, headers, iocs, geo}. Returns a DiGraph."""
    G = nx.DiGraph()

    def add(node_id, kind, label=None, **attrs):
        if not node_id:
            return None
        if node_id not in G:
            G.add_node(node_id, kind=kind, label=label or node_id, **attrs)
        return node_id

    for case in cases:
        parsed = case.get("parsed", {})
        iocs = case.get("iocs", {})
        geo = case.get("geo", {})
        headers = case.get("headers", {})

        case_id = "case:{}".format(case.get("name", "?"))
        add(case_id, "case", case.get("name", "?"),
            verdict=case.get("level", ""), score=case.get("score", 0))

        sender = parsed.get("from_addr")
        if sender:
            add(sender, "email", sender)
            G.add_edge(case_id, sender, rel="sent by")

        from_domain = parsed.get("from_domain")
        if from_domain:
            add(from_domain, "domain", from_domain)
            if sender:
                G.add_edge(sender, from_domain, rel="at domain")

        reply_to = parsed.get("reply_to")
        if reply_to and reply_to != sender:
            add(reply_to, "email", reply_to)
            G.add_edge(case_id, reply_to, rel="replies to")
            reply_domain = parsed.get("reply_to_domain")
            if reply_domain:
                add(reply_domain, "domain", reply_domain)
                G.add_edge(reply_to, reply_domain, rel="at domain")

        for domain in iocs.get("domains", [])[:6]:
            add(domain, "domain", domain)
            G.add_edge(case_id, domain, rel="links to")

        origin_record = geo.get("origin") or {}
        origin = origin_record.get("ip")
        if origin:
            add(origin, "ip", origin,
                country=origin_record.get("country", ""),
                isp=origin_record.get("isp", ""))
            G.add_edge(case_id, origin, rel="originated at")
            infra = origin_record.get("infra")
            if infra and infra not in ("corporate", "residential", "unknown"):
                infra_id = "infra:{}".format(infra)
                add(infra_id, "infra", origin_record.get("infra_label", infra))
                G.add_edge(origin, infra_id, rel="is")

        for hop in geo.get("hops", [])[1:4]:
            add(hop["ip"], "ip", hop["ip"],
                country=hop.get("country", ""), isp=hop.get("isp", ""))
            G.add_edge(case_id, hop["ip"], rel="relayed via")

        for wallet in iocs.get("wallets", [])[:3]:
            add(wallet, "wallet", wallet[:14] + "...")
            G.add_edge(case_id, wallet, rel="pay to")

        if headers.get("bec", {}).get("is_bec"):
            add("infra:bec", "infra", "BEC campaign")
            G.add_edge(case_id, "infra:bec", rel="matches")

    return G


def shared_indicators(G):
    """Artefacts touched by more than one case - the attribution payoff."""
    shared = []
    for node, data in G.nodes(data=True):
        if data.get("kind") == "case":
            continue
        cases = [n for n in G.predecessors(node)
                 if G.nodes[n].get("kind") == "case"]
        if len(cases) > 1:
            shared.append({
                "indicator": data.get("label", node),
                "kind": data.get("kind"),
                "cases": [G.nodes[c].get("label", c) for c in cases],
            })
    shared.sort(key=lambda s: len(s["cases"]), reverse=True)
    return shared


def graph_figure(G, height=520):
    """Plotly node-link diagram of the correlation graph."""
    if G.number_of_nodes() == 0:
        fig = go.Figure()
        fig.add_annotation(text="No indicators to correlate", showarrow=False)
        fig.update_layout(height=height)
        return fig

    try:
        pos = nx.spring_layout(G, seed=42, k=0.9, iterations=120)
    except Exception:
        pos = nx.circular_layout(G)

    edge_x, edge_y = [], []
    for src, dst in G.edges():
        x0, y0 = pos[src]
        x1, y1 = pos[dst]
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=edge_x, y=edge_y, mode="lines", hoverinfo="skip",
        line=dict(width=1, color="rgba(120,120,120,0.45)"), showlegend=False,
    ))

    for kind, style in NODE_STYLE.items():
        nodes = [n for n, d in G.nodes(data=True) if d.get("kind") == kind]
        if not nodes:
            continue
        hover = []
        for node in nodes:
            data = G.nodes[node]
            bits = ["<b>{}</b>".format(data.get("label", node)),
                    "type: {}".format(kind)]
            for key in ("country", "isp", "verdict"):
                if data.get(key):
                    bits.append("{}: {}".format(key, data[key]))
            bits.append("connections: {}".format(G.degree(node)))
            hover.append("<br>".join(bits))
        fig.add_trace(go.Scatter(
            x=[pos[n][0] for n in nodes], y=[pos[n][1] for n in nodes],
            mode="markers+text", name=kind,
            text=[G.nodes[n].get("label", n) for n in nodes],
            textposition="bottom center", textfont=dict(size=9),
            hovertext=hover, hoverinfo="text",
            marker=dict(size=style["size"], color=style["color"],
                        symbol=style["symbol"],
                        line=dict(width=1.5, color="white")),
        ))

    fig.update_layout(
        height=height, showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=1.01),
        margin=dict(l=10, r=10, t=30, b=10),
        xaxis=dict(visible=False), yaxis=dict(visible=False),
        plot_bgcolor="rgba(0,0,0,0)",
    )
    return fig


if __name__ == "__main__":
    G = build_graph([{
        "name": "demo", "level": "Critical", "score": 91,
        "parsed": {"from_addr": "a@evil.com", "from_domain": "evil.com",
                   "reply_to": "b@ru-drop.ru", "reply_to_domain": "ru-drop.ru"},
        "iocs": {"domains": ["bit.ly"], "wallets": []},
        "geo": {"origin": {"ip": "185.220.101.45", "infra": "tor",
                           "infra_label": "Tor exit node", "country": "Germany"},
                "hops": []},
        "headers": {"bec": {"is_bec": False}},
    }])
    print("nodes:", G.number_of_nodes(), " edges:", G.number_of_edges())
    print("shared:", shared_indicators(G))
    print("figure built:", type(graph_figure(G)).__name__)

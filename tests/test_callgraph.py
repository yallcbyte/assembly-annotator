from annotator.cil.callgraph import CallGraph, external, method


def graph(edges):
    g = CallGraph()
    for caller, target, kind in edges:
        g.add(caller, method(target) if isinstance(target, int) else external(target), kind)
    return g


# 1 -> 2 -> 3 -> 4,  1 -> 5 (delegate),  6 -> 2,  3 -> WebClient::DownloadString
SAMPLE = [(1, 2, 'call'), (2, 3, 'call'), (3, 4, 'callvirt'), (1, 5, 'ldftn'),
          (6, 2, 'call'), (3, 'System.Net.WebClient::DownloadString', 'callvirt'),
          (2, 'System.String::Concat', 'call')]


def test_callers_index_mirrors_callees():
    g = graph(SAMPLE)
    assert dict(g.callers[2]) == {1: 1, 6: 1}
    assert g.internal_callees(3) == {4: 1}


def test_repeated_calls_are_counted():
    g = graph([(1, 2, 'call'), (1, 2, 'call')])
    assert g.callees[1][(method(2), 'call')] == 2


def test_reachability_follows_calls_and_delegates():
    parents = graph(SAMPLE).reachable_from([1])
    assert set(parents) == {1, 2, 3, 4, 5}
    assert 6 not in parents          # 6 calls in, but nothing calls 6


def test_shortest_path_from_entry():
    g = graph(SAMPLE + [(1, 4, 'call')])
    parents = g.reachable_from([1])
    assert CallGraph.path(parents, 4) == [1, 4]
    assert CallGraph.path(parents, 3) == [1, 2, 3]
    assert CallGraph.path(parents, 6) is None


def test_cycles_terminate():
    g = graph([(1, 2, 'call'), (2, 3, 'call'), (3, 1, 'call')])
    assert set(g.reachable_from([1])) == {1, 2, 3}
    n = g.neighborhood(2, depth=3)
    assert n['layers'][method(2)] == 0


def test_neighborhood_layers():
    n = graph(SAMPLE).neighborhood(2, depth=2)
    layers = n['layers']
    assert layers[method(3)] == 1 and layers[method(4)] == 2
    assert layers[method(1)] == -1 and layers[method(6)] == -1
    assert layers[external('System.String::Concat')] == 1


def test_externals_only_appear_as_direct_callees():
    n = graph(SAMPLE).neighborhood(2, depth=2)
    # 3 calls DownloadString, but 3 is two hops from the focus 2... it is one hop.
    # From focus 1, DownloadString is two hops away and must be left out.
    n1 = graph(SAMPLE).neighborhood(1, depth=3)
    assert external('System.Net.WebClient::DownloadString') not in n1['layers']
    assert external('System.Net.WebClient::DownloadString') not in n['layers']


def test_edges_connect_only_placed_nodes():
    n = graph(SAMPLE).neighborhood(2, depth=1)
    placed = set(n['layers'])
    assert all(e['from'] in placed and e['to'] in placed for e in n['edges'])
    assert {'from': method(1), 'to': method(2), 'kind': 'call', 'count': 1} in n['edges']


def test_layer_cap_keeps_the_highest_priority_and_reports_the_rest():
    edges = [(1, r, 'call') for r in range(10, 40)]
    flagged = {25, 33}
    prio = lambda key, w: (0 if key[1] in flagged else 1, -w, key[1])
    n = graph(edges).neighborhood(1, depth=1, cap=5, priority=prio)
    kept = [k[1] for k, d in n['layers'].items() if d == 1]
    assert len(kept) == 5 and flagged <= set(kept)
    assert n['overflow'] == {1: 25}


def test_isolated_method_has_only_itself():
    n = CallGraph().neighborhood(7)
    assert n['layers'] == {method(7): 0} and n['edges'] == []


def test_implicit_callees_such_as_static_constructors_are_reached():
    # 1 calls 2; 2's type has a static constructor 9 that nobody calls
    # explicitly, and 9 calls 10.
    g = graph([(1, 2, 'call'), (9, 10, 'call')])
    cctor_of = {2: [9]}
    parents = g.reachable_from([1], implicit=lambda r: cctor_of.get(r, []))
    assert {9, 10} <= set(parents)
    assert CallGraph.path(parents, 10) == [1, 2, 9, 10]

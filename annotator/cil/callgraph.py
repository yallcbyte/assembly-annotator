"""Method-level call graph.

Nodes are methods in the assembly (`('m', row)`) or external APIs it calls
(`('x', 'System.Net.WebClient::DownloadString')`). Edges carry the opcode
that made them: call, callvirt, newobj, or ldftn for a delegate target.

Kept free of metadata so cycles, caps and reachability can be tested with
plain integers.
"""

from collections import Counter, defaultdict, deque
from typing import Callable, Dict, Iterable, List, Optional

CALL_KINDS = {'call', 'callvirt', 'newobj', 'jmp', 'ldftn', 'ldvirtftn', 'calli'}


def method(row: int):
    return ('m', row)


def external(name: str):
    return ('x', name)


class CallGraph:
    def __init__(self):
        self.callees: Dict[int, Counter] = defaultdict(Counter)   # row -> {(key, kind): n}
        self.callers: Dict[int, Counter] = defaultdict(Counter)   # row -> {caller row: n}
        self.external_callers: Dict[str, Counter] = defaultdict(Counter)

    def add(self, caller: int, target, kind: str):
        self.callees[caller][(target, kind)] += 1
        if target[0] == 'm':
            self.callers[target[1]][caller] += 1
        else:
            self.external_callers[target[1]][caller] += 1

    def internal_callees(self, row: int) -> Counter:
        out = Counter()
        for (key, _kind), n in self.callees.get(row, {}).items():
            if key[0] == 'm':
                out[key[1]] += n
        return out

    # ---- reachability ------------------------------------------------
    def reachable_from(self, roots: Iterable[int],
                       implicit: Optional[Callable[[int], Iterable[int]]] = None
                       ) -> Dict[int, Optional[int]]:
        """Breadth-first over internal edges; maps each reached row to its parent.

        `implicit(row)` names methods that run because `row` ran without being
        called explicitly -- in .NET, the static constructor of row's type.
        """
        parents: Dict[int, Optional[int]] = {}
        queue = deque()
        for r in roots:
            if r not in parents:
                parents[r] = None
                queue.append(r)
        while queue:
            row = queue.popleft()
            nexts = list(self.internal_callees(row))
            if implicit is not None:
                nexts.extend(implicit(row))
            for callee in nexts:
                if callee not in parents:
                    parents[callee] = row
                    queue.append(callee)
        return parents

    @staticmethod
    def path(parents: Dict[int, Optional[int]], target: int, limit: int = 64) -> Optional[List[int]]:
        """Shortest root-to-target chain, or None if target was not reached."""
        if target not in parents:
            return None
        chain = [target]
        while parents[chain[-1]] is not None and len(chain) < limit:
            chain.append(parents[chain[-1]])
        return list(reversed(chain))

    # ---- neighbourhood -----------------------------------------------------
    def neighborhood(self, focus: int, depth: int = 2, cap: int = 24,
                     priority: Optional[Callable] = None) -> dict:
        """Callers to the left (negative layers), callees to the right.

        External APIs appear only as direct callees of the focus method; at
        deeper levels they would swamp the picture with String.Concat and
        friends. Each layer keeps its `cap` highest-priority nodes and
        reports how many it dropped.
        """
        priority = priority or (lambda key, weight: (0, -weight))
        layer = {method(focus): 0}
        overflow: Dict[int, int] = {}

        frontier = [focus]
        for d in range(1, depth + 1):
            weights = Counter()
            for row in frontier:
                for (key, _kind), n in self.callees.get(row, {}).items():
                    if key in layer or (key[0] == 'x' and d > 1):
                        continue
                    weights[key] += n
            kept = sorted(weights, key=lambda k: priority(k, weights[k]))
            if len(kept) > cap:
                overflow[d] = len(kept) - cap
                kept = kept[:cap]
            for key in kept:
                layer[key] = d
            frontier = [k[1] for k in kept if k[0] == 'm']

        frontier = [focus]
        for d in range(1, depth + 1):
            weights = Counter()
            for row in frontier:
                for caller, n in self.callers.get(row, {}).items():
                    key = method(caller)
                    if key not in layer:
                        weights[key] += n
            kept = sorted(weights, key=lambda k: priority(k, weights[k]))
            if len(kept) > cap:
                overflow[-d] = len(kept) - cap
                kept = kept[:cap]
            for key in kept:
                layer[key] = -d
            frontier = [k[1] for k in kept]

        edges = []
        for key in layer:
            if key[0] != 'm':
                continue
            per_target = defaultdict(Counter)
            for (target, kind), n in self.callees.get(key[1], {}).items():
                if target in layer:
                    per_target[target][kind] += n
            for target, kinds in per_target.items():
                edges.append({'from': key, 'to': target,
                              'kind': kinds.most_common(1)[0][0],
                              'count': sum(kinds.values())})
        return {'layers': layer, 'edges': edges, 'overflow': overflow}

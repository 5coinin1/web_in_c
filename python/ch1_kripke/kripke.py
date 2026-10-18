"""Finite explicit-state Kripke graphs. No eval and no third-party packages."""
from collections import deque
import json
from pathlib import Path


class Kripke:
    def __init__(self, data):
        if isinstance(data, (str, Path)):
            data = json.loads(Path(data).read_text(encoding="utf-8"))
        self.data = data
        self.states = {s["id"]: s for s in data["states"]}
        if not self.states or len(self.states) != len(data["states"]):
            raise ValueError("Empty graph or duplicate state ID")
        self.initial = list(dict.fromkeys(data["initial_states"]))
        if not self.initial or not set(self.initial) <= self.states.keys():
            raise ValueError("Invalid initial set")
        self.labels = {k: set(v["labels"]) for k, v in self.states.items()}
        self.edges = {s: [] for s in self.states}
        seen = set()
        for i, edge in enumerate(data["transitions"]):
            if edge["from"] not in self.states or edge["to"] not in self.states:
                raise ValueError("Unknown edge endpoint")
            eid = edge.get("id", f"E{i}")
            if eid in seen:
                raise ValueError("Duplicate edge ID")
            seen.add(eid)
            self.edges[edge["from"]].append(dict(edge, id=eid))
        if any(not es for es in self.edges.values()):
            raise ValueError("CTL graph must be total; add terminal STUTTER explicitly")

    def bfs(self, initial=None):
        parents = {s: None for s in (self.initial if initial is None else initial)}
        distances = {s: 0 for s in parents}
        queue = deque(parents)
        while queue:
            s = queue.popleft()
            for e in self.edges[s]:
                t = e["to"]
                if t not in parents:
                    parents[t] = e
                    distances[t] = distances[s] + 1
                    queue.append(t)
        return parents, distances

    @staticmethod
    def trace(parents, target):
        states, edges = [target], []
        while parents[target] is not None:
            edge = parents[target]
            edges.append(edge)
            target = edge["from"]
            states.append(target)
        edges.reverse()
        return {"states": states[::-1], "edge_ids": [e["id"] for e in edges],
                "events": [e["event"] for e in edges]}

    def find(self, predicate, initial=None, bound=None):
        if bound is not None and (not isinstance(bound, int) or bound < 0):
            raise ValueError("Bound must be a nonnegative integer")
        parents = {s: None for s in (self.initial if initial is None else initial)}
        queue = deque((s, 0) for s in parents)
        while queue:
            s, depth = queue.popleft()
            if predicate(self.labels[s]):
                return self.trace(parents, s)
            if bound is not None and depth == bound:
                continue
            for e in self.edges[s]:
                if e["to"] not in parents:
                    parents[e["to"]] = e
                    queue.append((e["to"], depth + 1))
        return None

    def ag_not(self, predicate):
        trace = self.find(predicate)
        return {"holds": trace is None, "counterexample": trace}

    def ag_implies(self, premise, conclusion):
        result = self.ag_not(lambda labels: premise(labels) and not conclusion(labels))
        result["vacuous"] = self.find(premise) is None
        return result

    def ef(self, predicate):
        trace = self.find(predicate)
        return {"holds": trace is not None, "witness": trace}

    def ag_ef(self, premise, goal):
        """For every reachable p-state, a q-state is reachable (not AF q)."""
        parents, _ = self.bfs()
        goals = {s for s, labels in self.labels.items() if goal(labels)}
        reverse = {s: [] for s in self.states}
        for s, edges in self.edges.items():
            for edge in edges:
                reverse[edge["to"]].append(s)
        can_reach, queue = set(goals), deque(sorted(goals))
        while queue:
            for s in reverse[queue.popleft()]:
                if s not in can_reach:
                    can_reach.add(s)
                    queue.append(s)
        for s in parents:
            if premise(self.labels[s]) and s not in can_reach:
                return {"holds": False, "counterexample": self.trace(parents, s),
                        "reason": "No goal state reachable from final state"}
        return {"holds": True, "counterexample": None}


def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")

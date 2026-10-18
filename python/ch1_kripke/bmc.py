"""Optional bounded reachability helper for team handoff; no Z3 dependency.
This is explicit-state bounded checking, not SAT/SMT-based BMC.
"""

def completeness_threshold(model):
    return max(model.bfs()[1].values())


def check_invariant(model, invariant, bound):
    trace = model.find(lambda labels:not invariant(labels), bound=bound)
    return {"holds_up_to_bound":trace is None,"bound":bound,"counterexample":trace,
            "complete_for_state_invariant":bound >= completeness_threshold(model)}

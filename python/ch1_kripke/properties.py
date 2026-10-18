"""CTL requirements over the WebSocket command-boundary graph."""

def verify(model):
    has = lambda atom: lambda labels: atom in labels
    result = {}
    def add(pid, formula, value):
        result[pid] = dict(formula=formula, **value)
    add("P1","AG(in_room -> authenticated)",model.ag_implies(has("in_room"),has("authenticated")))
    add("P2","AG(authenticated -> ws_open)",model.ag_implies(has("authenticated"),has("ws_open")))
    add("P3","AG(closed -> NOT(authenticated OR member OR ws_open))",
        model.ag_implies(has("closed"),lambda l:not ({"authenticated","member","ws_open"}&l)))
    add("P4","AG(message_accepted -> (authenticated AND member AND in_room))",
        model.ag_implies(has("message_accepted"),lambda l:{"authenticated","member","in_room"}<=l))
    add("P5","AG(logged_out -> NOT(authenticated OR member OR in_room))",
        model.ag_implies(has("logged_out"),lambda l:not ({"authenticated","member","in_room"}&l)))
    add("P6","AG(member <-> in_room)",model.ag_not(lambda l:("member" in l)!=("in_room" in l)))
    add("P7","AG(authenticated -> (phase_AUTHENTICATED OR phase_IN_ROOM))",
        model.ag_implies(has("authenticated"),lambda l:bool({"phase_AUTHENTICATED","phase_IN_ROOM"}&l)))
    for pid, atom in [("R1","authenticated"),("R2","in_room"),("R3","message_accepted"),
                      ("R4","logged_out"),("R5","closed")]:
        add(pid,"EF "+atom,model.ef(has(atom)))
    add("L1","AG(ws_open -> EF(in_room OR closed))",model.ag_ef(has("ws_open"),lambda l:bool({"in_room","closed"}&l)))
    add("L2","AG(in_room -> EF(authenticated AND NOT in_room))",
        model.ag_ef(has("in_room"),lambda l:"authenticated" in l and "in_room" not in l))
    return result

"""Small shared-state abstractions; not concrete-thread execution proofs."""
from collections import deque


def build_shared(core, same_account=False, broken_delete=False):
    table = {(e["from"],e["event"]):e["to"] for e in core["matrix"] if e["accepted"]}
    # (phase_A, phase_B, auth_A, auth_B, member_A, member_B, room_exists)
    initial = (core["initial"], core["initial"], False, False, False, False, True)
    ids, queue, states, edges = {initial:"G0"}, deque([initial]), [], []
    while queue:
        s = queue.popleft()
        labels = []
        if s[2] and s[3]: labels.append("both_authenticated")
        if s[4] or s[5]: labels.append("has_members")
        if s[6]: labels.append("room_exists")
        if all((s[i]=="IN_ROOM")==s[4+i] for i in range(2)): labels.append("membership_consistent")
        if all(not s[4+i] or s[2+i] for i in range(2)): labels.append("members_authenticated")
        states.append(dict(id=ids[s], phases=list(s[:2]), auth=list(s[2:4]), members=list(s[4:6]),
                           room_exists=s[6], labels=labels))
        outgoing = []
        for role in range(2):
            for event in core["events"]:
                if (s[role],event) not in table: continue
                if event == "ROOM_CLOSED": continue  # shared admin operation, not local
                t = list(s)
                actual = event
                if event == "LOGIN_OK" and same_account and s[2+(1-role)]:
                    actual = "LOGIN_FAIL"
                if event == "JOIN_OK" and not s[6]: actual = "JOIN_FAIL"
                t[role] = table[(s[role],actual)]
                if actual == "LOGIN_OK": t[2+role] = True
                if actual == "JOIN_OK": t[4+role] = True
                if actual == "LEAVE_OK": t[4+role] = False
                if actual in ("LOGOUT","DISCONNECT"):
                    t[2+role] = False
                    t[4+role] = False
                outgoing.append((tuple(t), f"{'AB'[role]}:{event}:{actual}"))
        if s[6]:
            t = list(s)
            t[6] = False
            for role in range(2):
                if s[4+role] and not (broken_delete and role==1):
                    t[role] = table[(s[role],"ROOM_CLOSED")]
                    t[4+role] = False
            outgoing.append((tuple(t),"ADMIN_DELETE_ROOM"))
        else:
            t = list(s); t[6] = True
            outgoing.append((tuple(t),"ADMIN_CREATE_ROOM"))
        for target,event in outgoing:
            if target not in ids:
                ids[target] = f"G{len(ids)}"; queue.append(target)
            edges.append(dict(id=f"G_E{len(edges)}", **{"from":ids[s],"to":ids[target]},event=event))
    return dict(schema_version=1, name="shared_"+("same_account" if same_account else "distinct_accounts")+
                ("_buggy_delete" if broken_delete else ""),initial_states=["G0"],states=states,transitions=edges,
                abstraction="two connections, atomic session acquire/release, one shared room, atomic commands")


def leave_window_model():
    """Diagnostic projection of the existing multi-step client_leave_room().
    Does not assert a concrete data-race exploit or make scheduling claims.
    """
    rows = [
        ("L0",["in_room","room_ref","member"],"before room_leave"),
        ("L1",["in_room","room_ref","mismatch"],"after room_leave removes membership"),
        ("L2",["in_room","mismatch"],"after client->room[0] = 0"),
        ("L3",[],"after client_state_apply(LEAVE_OK)"),
    ]
    return dict(name="leave_nonatomic_diagnostic",initial_states=["L0"],
                states=[dict(id=i,labels=l,description=d) for i,l,d in rows],
                transitions=[dict(id=f"D{i}",**{"from":a,"to":b},event=e)
                  for i,(a,b,e) in enumerate([("L0","L1","room_leave"),("L1","L2","clear_room_ref"),
                                              ("L2","L3","LEAVE_OK"),("L3","L3","STUTTER")])])

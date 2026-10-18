"""Command-boundary abstraction reviewed against connection.c and room.c.
Lifecycle edges are composed from the C-exported transition relation.
Command guards below are explicit abstractions, not automatically extracted C.
"""
from collections import deque
from dataclasses import dataclass

PHASES = ("IDLE", "HTTP_HANDSHAKE", "WS_CONNECTED", "AUTHENTICATED", "IN_ROOM", "CLOSED")
WS = PHASES[2:5]


@dataclass(frozen=True)
class State:
    phase: str
    auth: bool = False
    member: bool = False
    effect: str = "NONE"


def build_model(core, mutation="none"):
    if tuple(core["states"]) != PHASES:
        raise ValueError("C state list changed; review command abstraction")
    table = {(e["from"], e["event"]): e["to"] for e in core["matrix"] if e["accepted"]}
    def apply(s, events, effect="NONE"):
        phase, auth, member = s.phase, s.auth, s.member
        for event in events:
            if mutation == "join_bypass" and phase == "WS_CONNECTED" and event == "JOIN_OK":
                phase = "IN_ROOM"
            else:
                phase = table[(phase, event)]
            if event == "LOGIN_OK": auth = True
            if event == "JOIN_OK": member = True
            if event in ("LEAVE_OK", "ROOM_CLOSED"): member = False
            if event in ("LOGOUT", "DISCONNECT"):
                if not (mutation == "stale_auth" and event == "LOGOUT"):
                    auth = False
                member = False
        return State(phase, auth, member, effect)

    def transitions(s):
        def edge(event, events=(), result="OK", effect="NONE", source="connection.c", guard=""):
            return (apply(s, events, effect), dict(event=event, core_events=list(events),
                    result=result, source=source, guard=guard, kind="command"))
        if s.phase == "CLOSED":
            yield s, dict(event="STUTTER", core_events=[], result="TERMINAL",
                          source="CTL totalization", guard="closed", kind="model")
            return
        # At a command boundary, destruction includes room/session cleanup.
        cleanup = ["LEAVE_OK"] if s.phase == "IN_ROOM" else []
        for event in ("TCP_DISCONNECT", "IDLE_TIMEOUT"):
            yield edge(event, cleanup+["DISCONNECT"], "CLOSED", source="connection.c:client_destroy / server.c")
        if s.phase == "IDLE":
            yield edge("FIRST_BYTES", ["ACCEPT"], source="connection.c:client_process_buffer")
            return
        if s.phase == "HTTP_HANDSHAKE":
            yield edge("HTTP_PARTIAL", result="WAIT")
            yield edge("HTTP_UPGRADE_VALID", ["HTTP_UPGRADE_OK"], "UPGRADED")
            yield edge("HTTP_UPGRADE_INVALID", ["DISCONNECT"], "CLOSED")
            return
        for event, result in [("FRAME_PARTIAL","WAIT"), ("FRAME_OTHER_OPCODE","IGNORED"),
                              ("TEXT_EMPTY","IGNORED"), ("TEXT_MISSING_TYPE","IGNORED"),
                              ("COMMAND_UNKNOWN","IGNORED"), ("WS_PONG","IGNORED"),
                              ("WS_PING","PONG_ATTEMPT"), ("PING","PONG_ATTEMPT")]:
            yield edge(event, result=result)
        for event in ("WS_CLOSE", "FRAME_INVALID"):
            yield edge(event, cleanup+["DISCONNECT"], "CLOSED")
        for outcome in ("OK", "MISSING_FIELDS", "EXISTS", "INVALID", "IO_ERROR"):
            allowed = s.phase == "WS_CONNECTED"
            result = "REGISTER_OK" if allowed and outcome == "OK" else "REGISTER_FAIL"
            yield edge("REGISTER_"+outcome, result=result, guard="phase == WS_CONNECTED; payload/outcome abstracted")
        for outcome in ("OK", "MISSING_CREDENTIALS", "BAD_CREDENTIALS", "LOCKED", "SESSION_DUP", "SESSION_FULL"):
            if s.phase != "WS_CONNECTED":
                yield edge("LOGIN_"+outcome, result="ERROR_ALREADY_LOGGED_IN")
            else:
                event = "LOGIN_OK" if outcome == "OK" else "LOGIN_FAIL"
                yield edge("LOGIN_"+outcome, [event], event, guard="auth_check then session_add")
        allowed = s.phase in ("AUTHENTICATED", "IN_ROOM")
        yield edge("ROOMS", result="ROOM_LIST" if allowed else "ERROR_LOGIN_REQUIRED")
        for outcome in ("OK", "INVALID_ROOM", "BAD_CODE", "NOT_FOUND", "FULL", "BAD_STATE"):
            if mutation == "join_bypass" and s.phase == "WS_CONNECTED" and outcome == "OK":
                yield edge("JOIN_"+outcome, ["JOIN_OK"], "JOINED", guard="MUTATED login guard")
            elif s.phase == "IN_ROOM":
                yield edge("JOIN_"+outcome, result="JOIN_FAIL_LEAVE_FIRST")
            elif s.phase != "AUTHENTICATED":
                yield edge("JOIN_"+outcome, result="ERROR_LOGIN_REQUIRED")
            elif outcome == "OK":
                yield edge("JOIN_OK", ["JOIN_OK"], "JOINED", source="room.c:room_join_commit")
            else:
                events = [] if outcome == "INVALID_ROOM" else ["JOIN_FAIL"]
                yield edge("JOIN_"+outcome, events, "JOIN_FAIL", source="connection.c / room.c")
        yield edge("LEAVE", ["LEAVE_OK"] if s.phase == "IN_ROOM" else [], "LEFT")
        if s.phase in ("AUTHENTICATED", "IN_ROOM"):
            yield edge("LOGOUT", cleanup+["LOGOUT"], "LOGGED_OUT", effect="LOGOUT")
        else:
            yield edge("LOGOUT", result="ERROR_NOT_LOGGED_IN")
        for outcome in ("VALID", "MISSING_CONTENT"):
            allowed = s.phase == "IN_ROOM" or (mutation == "message_guard" and s.phase == "AUTHENTICATED")
            if not allowed:
                yield edge("MESSAGE_"+outcome, result="ERROR_NOT_IN_ROOM")
            elif outcome != "VALID":
                yield edge("MESSAGE_"+outcome, result="IGNORED")
            else:
                yield edge("MESSAGE_VALID", result="BROADCAST_ATTEMPT", effect="MESSAGE",
                           guard="phase == IN_ROOM; valid content")
        yield edge("LIST", result="USER_LIST" if s.phase == "IN_ROOM" else "ERROR_NOT_IN_ROOM")
        if s.phase == "IN_ROOM":
            yield edge("ADMIN_DELETE_CURRENT_ROOM", ["ROOM_CLOSED"], "ROOM_CLOSED", source="room.c:room_delete")

    initial = State(core["initial"])
    ids, queue = {initial: "S0"}, deque([initial])
    states, edges = [], []
    while queue:
        s = queue.popleft()
        labels = ["phase_"+s.phase]
        if s.phase in WS: labels.append("ws_open")
        if s.phase == "CLOSED": labels.append("closed")
        if s.phase == "IN_ROOM": labels.append("in_room")
        if s.auth: labels.append("authenticated")
        if s.member: labels.append("member")
        if s.effect == "MESSAGE": labels.append("message_accepted")
        if s.effect == "LOGOUT": labels.append("logged_out")
        states.append(dict(id=ids[s], phase=s.phase, auth_history=s.auth, member=s.member,
                           last_effect=s.effect, labels=labels))
        for target, info in transitions(s):
            if target not in ids:
                ids[target] = f"S{len(ids)}"
                queue.append(target)
            edges.append(dict(id=f"E{len(edges)}", **{"from":ids[s], "to":ids[target]}, **info))
    return dict(schema_version=1, name="websocket_"+mutation, initial_states=["S0"],
                abstraction="one connection, one current room, atomic command boundaries",
                states=states, transitions=edges)

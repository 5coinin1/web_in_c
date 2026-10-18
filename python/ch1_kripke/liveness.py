"""Existential progress at command boundaries; does not prove inevitability."""

def check_progress(model):
    return {
        "room_or_close": model.ag_ef(lambda l:"ws_open" in l,lambda l:bool({"in_room","closed"}&l)),
        "leave_possible": model.ag_ef(lambda l:"in_room" in l,lambda l:"authenticated" in l and "in_room" not in l),
    }

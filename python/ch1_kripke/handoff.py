"""Generate reviewable model-based test vectors, diagram and C core tests."""
import csv
import json
from pathlib import Path
try:
    from .kripke import write_json
except ImportError:
    from kripke import write_json


def export_model(model, directory):
    directory = Path(directory)
    directory.mkdir(parents=True,exist_ok=True)
    write_json(directory/"model.json",model.data)
    with (directory/"transitions.csv").open("w",encoding="utf-8",newline="") as f:
        columns = ["id","from","event","to","result","core_events","source","guard"]
        writer=csv.DictWriter(f,fieldnames=columns,extrasaction="ignore")
        writer.writeheader()
        for edge in model.data["transitions"]:
            writer.writerow(dict(edge,core_events=";".join(edge.get("core_events",[]))))
    lines=["digraph Kripke {", "rankdir=LR;"]
    for s in model.data["states"]:
        label=s["id"]+" "+s.get("phase","")+"\\n"+", ".join(s["labels"])
        lines.append(f'{s["id"]} [label={json.dumps(label)}];')
    for e in model.data["transitions"]:
        lines.append(f'{e["from"]} -> {e["to"]} [label={json.dumps(e["event"])}];')
    lines.append("}")
    (directory/"model.dot").write_text("\n".join(lines)+"\n",encoding="utf-8")
    parents,_=model.bfs()
    # One shortest prefix plus each edge, including self-loops/rejections.
    cases=[]
    for e in model.data["transitions"]:
        if e["from"] not in parents or e["event"]=="STUTTER":continue
        prefix=model.trace(parents,e["from"])
        cases.append(dict(id=e["id"],events=prefix["events"]+[e["event"]],
                          expected_state=e["to"],expected_result=e.get("result"),
                          scope="abstract command model; network adapter required"))
    write_json(directory/"test_vectors.json",dict(schema_version=1,cases=cases))
    return cases


def generate_core_tests(core, path):
    """Snapshot assertions for all C state/event pairs. Not an independent spec."""
    lines=['/* Generated baseline regression tests. Review before use as an oracle. */',
           '#include "state_machine.h"','#include <stdio.h>','int main(void) {',
           'int failures = 0; client_state_t next; bool accepted;']
    for e in core["matrix"]:
        lines += [f'next = STATE_{e["from"]};',
                  f'accepted = client_state_apply(&next, CLIENT_EVENT_{e["event"]});',
                  f'if (accepted != {str(e["accepted"]).lower()} || next != STATE_{e["to"]}) {{',
                  f'puts("FAIL {e["from"]} / {e["event"]}"); ++failures; }}']
    lines += ['printf("Core snapshot regression: %d failures\\n", failures);','return failures ? 1 : 0;','}']
    Path(path).write_text("\n".join(lines)+"\n",encoding="utf-8")

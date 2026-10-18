"""Run WebSocket-only model checks and C state-machine replay."""
import argparse
from collections import deque
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import platform
import subprocess
import sys
import traceback

if __package__:
    from .kripke import Kripke, write_json
    from .model import build_model
    from .products import build_shared, leave_window_model
    from .properties import verify
    from .bmc import completeness_threshold, check_invariant
    from .handoff import export_model, generate_core_tests
else:
    from kripke import Kripke, write_json
    from model import build_model
    from products import build_shared, leave_window_model
    from properties import verify
    from bmc import completeness_threshold, check_invariant
    from handoff import export_model, generate_core_tests

BASE=Path(__file__).resolve().parent
ROOT=BASE.parents[1]


def run(bridge, output):
    count=0
    def check(name, condition):
        nonlocal count
        if not condition: raise AssertionError(name)
        count+=1
        print('[TEST PASS]',name)
    def call(events=(), mutant=False):
        return subprocess.run([str(bridge),*(['--buggy-join'] if mutant else []),*events],
                              capture_output=True,text=True,encoding='utf-8',errors='replace')
    exported=call(['--export'])
    check('C export succeeds',exported.returncode==0)
    core=json.loads(exported.stdout)
    write_json(output/'core_matrix.json',core)
    print('WEB SOCKET KRIPKE VERIFICATION',platform.system(),platform.python_version())
    # Independent, reviewed expected contract for the six-state machine.
    expected={
        'IDLE':{'ACCEPT':'HTTP_HANDSHAKE','DISCONNECT':'CLOSED'},
        'HTTP_HANDSHAKE':{'HTTP_UPGRADE_OK':'WS_CONNECTED','DISCONNECT':'CLOSED'},
        'WS_CONNECTED':{'LOGIN_OK':'AUTHENTICATED','LOGIN_FAIL':'WS_CONNECTED','DISCONNECT':'CLOSED'},
        'AUTHENTICATED':{'JOIN_OK':'IN_ROOM','JOIN_FAIL':'AUTHENTICATED','LOGOUT':'WS_CONNECTED','DISCONNECT':'CLOSED'},
        'IN_ROOM':{'LEAVE_OK':'AUTHENTICATED','ROOM_CLOSED':'AUTHENTICATED','DISCONNECT':'CLOSED'},
        'CLOSED':{},
    }
    check('C initial state is IDLE',core['initial']=='IDLE')
    check('six C states match reviewed contract',set(core['states'])==set(expected))
    check('ten C events match reviewed contract',set(core['events'])=={
        'ACCEPT','HTTP_UPGRADE_OK','LOGIN_OK','LOGIN_FAIL','JOIN_OK','JOIN_FAIL',
        'LEAVE_OK','ROOM_CLOSED','LOGOUT','DISCONNECT'})
    check('complete matrix without duplicate pairs',len(core['matrix'])==60 and
          len({(e['from'],e['event']) for e in core['matrix']})==60)
    prefixes={'IDLE':[]}; queue=deque(['IDLE'])
    while queue:
        s=queue.popleft()
        for event,target in expected[s].items():
            if target not in prefixes:
                prefixes[target]=prefixes[s]+[event];queue.append(target)
    for edge in core['matrix']:
        s,event=edge['from'],edge['event']
        target=expected[s].get(event,s)
        accepted=event in expected[s]
        check('core contract '+s+'/'+event,edge['accepted']==accepted and edge['to']==target)
        replay=call(prefixes[s]+[event]); result=json.loads(replay.stdout)
        check('C replay '+s+'/'+event,replay.returncode==(0 if accepted else 2)
              and result['final']==target and result['steps'][-1]['accepted']==accepted)
    results={}
    graphs={}
    for mutation,expected_failure in [('none',None),('join_bypass','P1'),('message_guard','P4'),('stale_auth','P5')]:
        model=Kripke(build_model(core,mutation));graphs[mutation]=model
        props=verify(model);results[mutation]=props
        print('\nMODEL',mutation,'states=',len(model.states),'edges=',len(model.data['transitions']))
        for pid,p in props.items():
            print(pid,p['formula'],'PASS' if p['holds'] else 'FAIL',
                  p.get('counterexample') or p.get('witness') or '')
        if expected_failure is None:
            check('SAFE satisfies all required properties',all(p['holds'] for p in props.values()))
            check('SAFE implications are nonvacuous',not any(p.get('vacuous') for p in props.values()))
        else:
            check('mutation detected '+mutation,not props[expected_failure]['holds'])
            trace=props[expected_failure]['counterexample']
            write_json(output/(mutation+'_counterexample.json'),trace)
        threshold=completeness_threshold(model)
        invariant=lambda l:not ('in_room' in l and 'authenticated' not in l)
        bounded=check_invariant(model,invariant,threshold)
        check('bounded helper agrees with BFS '+mutation,bounded['holds_up_to_bound']==props['P1']['holds'])
        print('Completeness threshold for state invariants:',threshold)
        export_model(model,output/mutation)
    safe=graphs['none']
    def follow(events, model=safe):
        current=model.initial[0];last=None
        for event in events:
            choices=[e for e in model.edges[current] if e['event']==event]
            if len(choices)!=1:raise AssertionError('ambiguous/missing event '+event)
            last=choices[0];current=last['to']
        return model.states[current],last
    connected=['FIRST_BYTES','HTTP_UPGRADE_VALID']
    authenticated=connected+['LOGIN_OK']
    inside=authenticated+['JOIN_OK']
    scenarios=[
        ('register does not authenticate',connected+['REGISTER_OK'],'WS_CONNECTED','REGISTER_OK',False,False),
        ('bad password stays unauthenticated',connected+['LOGIN_BAD_CREDENTIALS'],'WS_CONNECTED','LOGIN_FAIL',False,False),
        ('duplicate session denied',connected+['LOGIN_SESSION_DUP'],'WS_CONNECTED','LOGIN_FAIL',False,False),
        ('join requires login',connected+['JOIN_OK'],'WS_CONNECTED','ERROR_LOGIN_REQUIRED',False,False),
        ('message requires room',authenticated+['MESSAGE_VALID'],'AUTHENTICATED','ERROR_NOT_IN_ROOM',True,False),
        ('list requires room',authenticated+['LIST'],'AUTHENTICATED','ERROR_NOT_IN_ROOM',True,False),
        ('rooms requires login',connected+['ROOMS'],'WS_CONNECTED','ERROR_LOGIN_REQUIRED',False,False),
        ('wrong room code rejected',authenticated+['JOIN_BAD_CODE'],'AUTHENTICATED','JOIN_FAIL',True,False),
        ('switch room requires leave',inside+['JOIN_OK'],'IN_ROOM','JOIN_FAIL_LEAVE_FIRST',True,True),
        ('message accepted in room',inside+['MESSAGE_VALID'],'IN_ROOM','BROADCAST_ATTEMPT',True,True),
        ('missing message ignored',inside+['MESSAGE_MISSING_CONTENT'],'IN_ROOM','IGNORED',True,True),
        ('logout in room composes leave then logout',inside+['LOGOUT'],'WS_CONNECTED','LOGGED_OUT',False,False),
        ('room deletion evicts member',inside+['ADMIN_DELETE_CURRENT_ROOM'],'AUTHENTICATED','ROOM_CLOSED',True,False),
        ('leave does not logout',inside+['LEAVE'],'AUTHENTICATED','LEFT',True,False),
        ('leave before login is idempotent',connected+['LEAVE'],'WS_CONNECTED','LEFT',False,False),
        ('ping before login allowed',connected+['PING'],'WS_CONNECTED','PONG_ATTEMPT',False,False),
        ('websocket ping keeps room',inside+['WS_PING'],'IN_ROOM','PONG_ATTEMPT',True,True),
        ('close clears session and membership',inside+['WS_CLOSE'],'CLOSED','CLOSED',False,False),
        ('invalid handshake closes',['FIRST_BYTES','HTTP_UPGRADE_INVALID'],'CLOSED','CLOSED',False,False),
        ('partial handshake waits',['FIRST_BYTES','HTTP_PARTIAL'],'HTTP_HANDSHAKE','WAIT',False,False),
    ]
    for name,events,phase,result,auth,member in scenarios:
        state,edge=follow(events)
        check(name,(state['phase'],edge['result'],state['auth_history'],state['member'])==(phase,result,auth,member))
    # Same underlying C steps for command-boundary lifecycle, including LOGOUT in room.
    edge_by_id={e['id']:e for e in safe.data['transitions']}
    parents,_=safe.bfs();unique=set()
    for edge in safe.data['transitions']:
        trace=safe.trace(parents,edge['from'])
        seq=[]
        for eid in trace['edge_ids']+[edge['id']]: seq.extend(edge_by_id[eid]['core_events'])
        seq=tuple(seq)
        if seq in unique:continue
        unique.add(seq)
        replay=call(seq);response=json.loads(replay.stdout)
        check('composed lifecycle replay '+str(len(unique)),replay.returncode==0 and
              response['final']==safe.states[edge['to']]['phase'])
    bad=graphs['join_bypass']; trace=results['join_bypass']['P1']['counterexample']
    bad_edges={e['id']:e for e in bad.data['transitions']}
    seq=[event for eid in trace['edge_ids'] for event in bad_edges[eid]['core_events']]
    check('shortest login bypass',seq==['ACCEPT','HTTP_UPGRADE_OK','JOIN_OK'])
    replay=call(seq,True);clean=call(seq)
    check('C injected bypass reproduces P1',replay.returncode==1 and json.loads(replay.stdout)['violation'])
    check('C original refuses bypass',clean.returncode==2)
    write_json(output/'c_counterexample_replay.json',dict(events=seq,buggy=json.loads(replay.stdout),safe=json.loads(clean.stdout)))
    check('bound two misses three-step bypass',check_invariant(bad,lambda l:not('in_room' in l and 'authenticated' not in l),2)['holds_up_to_bound'])
    shared_results={}
    for same,buggy in [(True,False),(False,False),(False,True)]:
        model=Kripke(build_shared(core,same,buggy))
        props={
            'membership_consistent':model.ag_not(lambda l:'membership_consistent' not in l),
            'members_authenticated':model.ag_not(lambda l:'members_authenticated' not in l),
            'deleted_room_empty':model.ag_implies(lambda l:'room_exists' not in l,lambda l:'has_members' not in l),
        }
        if same:props['single_session']=model.ag_not(lambda l:'both_authenticated' in l)
        else:props['two_accounts_can_login']=model.ef(lambda l:'both_authenticated' in l)
        name=model.data['name'];shared_results[name]=props
        print('\nSHARED MODEL',name,'states',len(model.states))
        for pid,value in props.items():print(pid,value)
        check('shared model expectation '+name,not props['deleted_room_empty']['holds'] if buggy else all(v['holds'] for v in props.values()))
        write_json(output/(name+'.json'),model.data)
    diagnostic=Kripke(leave_window_model())
    diag=diagnostic.ef(lambda l:'mismatch' in l)
    check('non-atomic leave diagnostic is reachable',diag['holds'])
    print('\nDIAGNOSTIC: atomic-command membership invariant does not hold between LEAVE implementation steps:',diag)
    write_json(output/'leave_window.json',diagnostic.data)
    # Check the generic checker on a cycle, an unreachable bad node, and two initial states.
    toy=Kripke(dict(initial_states=['A','C'],states=[dict(id=s,labels=['bad'] if s in 'BD' else []) for s in 'ABCD'],
        transitions=[dict(**{'from':a,'to':b},event=e) for a,b,e in [('A','A','loop'),('A','C','go'),('C','B','bad'),('B','B','loop'),('D','D','loop')]]))
    check('BFS multiple initial shortest trace',toy.ag_not(lambda l:'bad' in l)['counterexample']['states']==['C','B'])
    check('unreachable bad state excluded',set(toy.bfs()[0])=={'A','B','C'})
    check('AG EF detects impossible goal',not toy.ag_ef(lambda l:True,lambda l:'missing' in l)['holds'])
    check('EF false has no witness',toy.ef(lambda l:'missing' in l)=={'holds':False,'witness':None})
    check('implication detects vacuity',toy.ag_implies(lambda l:'missing' in l,lambda l:False)['vacuous'])
    generate_core_tests(core,output/'core_regression.c')
    write_json(output/'results.json',dict(command_models=results,shared_models=shared_results,leave_diagnostic=diag,tests_passed=count))
    source_files=['src/state_machine.c','src/state_machine.h','src/connection.c','src/room.c','src/session.c','src/server.c']
    hashes={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in source_files}
    write_json(output/'provenance.json',dict(platform=platform.platform(),python=sys.version,source_sha256=hashes,
              boundary='C core table executed; command/shared policies manually reviewed abstraction'))
    print('\nTOTAL:',count,'tests PASS')
    print('Only WebSocket models. Injected-model FAIL and LEAVE diagnostic are expected findings.')
    print('No claim of complete end-to-end network, scheduling, password or memory-safety verification.')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--bridge',required=True,type=Path)
    parser.add_argument('--output',type=Path,default=BASE/'generated')
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=True)
    transcript=io.StringIO();status=0
    with redirect_stdout(transcript):
        try:run(args.bridge.resolve(strict=True),args.output)
        except Exception:
            traceback.print_exc(file=sys.stdout);status=1
    text=transcript.getvalue()
    (args.output/'verification.txt').write_text(text,encoding='utf-8');print(text)
    return status


if __name__=='__main__':sys.exit(main())

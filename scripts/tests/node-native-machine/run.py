#!/usr/bin/env python3
"""Exclusive true Core/Workerman native Machine two-node application gate."""
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from tls_proxy import NativeTLSProxy
from preflight import inspect as compatibility_preflight
from native_setup import prepare as prepare_native, render_credentials
from recovery_diagnostic import FAILURE_CLASSES, valid_recovery

if len(sys.argv)!=4:raise SystemExit('usage: run.py API NODE NEW_EVIDENCE')
api,node,evidence=(Path(p).resolve() for p in sys.argv[1:]);scripts=Path(__file__).resolve().parent
# Pin application source independently of the candidate Node and fixture code.
baseline=json.loads((node/'compatibility/core.v1.json').read_text())
core=api.parent
actual=subprocess.check_output(['git','-C',str(core),'rev-parse','HEAD'],text=True).strip()
node_revision=subprocess.check_output(['git','-C',str(node),'rev-parse','HEAD'],text=True).strip()
node_tree=subprocess.check_output(['git','-C',str(node),'rev-parse','HEAD^{tree}'],text=True).strip()
core_tree=subprocess.check_output(['git','-C',str(core),'rev-parse','HEAD^{tree}'],text=True).strip()
if actual!=baseline['revision'] or baseline['repository']!='ANRCM0/TXBoard':
    raise SystemExit('NATIVE_MACHINE_IMMUTABLE_CORE_REQUIRED')
if subprocess.check_output(['git','-C',str(core),'diff','HEAD','--','api'],text=True).strip():
    raise SystemExit('NATIVE_MACHINE_CORE_SOURCE_MODIFIED')

expected={'APP_ENV':'testing','DB_CONNECTION':'mysql','DB_HOST':'127.0.0.1','DB_DATABASE':'txboard_native_machine_test','DB_USERNAME':'txboard_native_machine'}
if any(os.environ.get(k)!=v for k,v in expected.items()):raise SystemExit('NATIVE_MACHINE_EXCLUSIVE_FIXTURE_REQUIRED')
if evidence.exists() or not os.environ.get('DB_PASSWORD') or not(api/'artisan').is_file() or not(node/'go.mod').is_file():raise SystemExit('NATIVE_MACHINE_INPUT_REFUSED')
php=shutil.which('php84')or shutil.which('php');mysql=shutil.which('mariadb')or shutil.which('mysql')
if not php or not mysql or not shutil.which('go')or not shutil.which('openssl')or not shutil.which('node'):raise SystemExit('NATIVE_MACHINE_TOOLS_REQUIRED')
go=json.loads(subprocess.check_output(['go','env','-json','GOPATH','GOMODCACHE','GOCACHE','CGO_ENABLED'],text=True))
if any(not isinstance(go.get(k),str)or not go[k] for k in ('GOPATH','GOMODCACHE','GOCACHE'))or go.get('CGO_ENABLED')!='1':raise SystemExit('NATIVE_MACHINE_GO_RACE_ENV_REQUIRED')
env={k:os.environ[k]for k in ('PATH','LANG','LC_ALL','TMPDIR','GOTOOLCHAIN')if k in os.environ};env.update(go)
env['CORE_RELEASE_ID'] = actual
env.update(expected|{'DB_PORT':os.environ.get('DB_PORT','13306'),'DB_PASSWORD':os.environ['DB_PASSWORD'],'APP_DEBUG':'false','CACHE_DRIVER':'redis','SETTING_CACHE_STORE':'redis','SESSION_DRIVER':'array','QUEUE_CONNECTION':'sync','MAIL_MAILER':'array','CORE_INSTALLATION_MODE':'legacy','CORE_INSTALLATION_EPOCH':'1','TXBOARD_NATIVE_NODE_WS_ENABLED':'true','APP_KEY':'base64:ZdD07lazsdQQmdBAJ2tA5WjufeI2hP8xlP6zgmvCMZs=','REDIS_HOST':'127.0.0.1','REDIS_PORT':os.environ.get('REDIS_PORT','16379'),'REDIS_DB':os.environ.get('REDIS_DB','14'),'REDIS_CACHE_DB':os.environ.get('REDIS_CACHE_DB','15'),'REDIS_PREFIX':'native-machine-'+hashlib.sha256(str(evidence).encode()).hexdigest()[:12]+':','NATIVE_MACHINE_API':str(api),'NATIVE_MACHINE_DIR':str(evidence)})
if not env['REDIS_DB'].isdigit() or not env['REDIS_CACHE_DB'].isdigit() or env['REDIS_DB']==env['REDIS_CACHE_DB']:
    raise SystemExit('NATIVE_MACHINE_DISTINCT_REDIS_DATABASES_REQUIRED')
evidence.mkdir(mode=0o700)

def artifact(name,value):
    target=evidence/name;temporary=evidence/(name+'.write')
    with temporary.open('x',encoding='utf-8')as output:
        os.chmod(temporary,0o600);json.dump(value,output,sort_keys=True,indent=2);output.write('\n');output.flush();os.fsync(output.fileno())
    os.rename(temporary,target)
    directory=os.open(evidence,os.O_RDONLY)
    try:os.fsync(directory)
    finally:os.close(directory)

artifact('sources.json',{'schema':'txnode-core-machine-sources/v1',
    'core_repository':baseline['repository'],'core_revision':actual,'core_tree':core_tree,'requested_core_release_id':actual,
    'node_repository':'ANRCM0/txnode','node_revision':node_revision,'node_tree':node_tree,
    'core_installation_mode':'not_started','requested_core_installation_mode':'native','node_kernel':'txnode',
    'fixture_ancestor':'TXBoard 52ae0ba154c27e9d8c9db4096edfb5ae2e7a8645 scripts/tests/node-native-machine',
    'native_core_installation_admission':False})
compatibility = compatibility_preflight(api, baseline)
artifact('compatibility-preflight.json', compatibility)
if compatibility['gaps']:
    result = {'schema': 'txnode-core-machine-result/v1', 'status': 'failed',
              'failed_stage': 'compatibility_preflight', 'core_revision': actual,
              'node_revision': node_revision, 'core_tree': core_tree, 'node_tree': node_tree,
              'core_installation_mode': 'not_started', 'requested_core_installation_mode': 'native', 'node_kernel': 'txnode',
              'native_core_installation_admission': False,
              'diagnostics': {'category': 'core_contract_gap', 'gaps': compatibility['gaps']}}
    artifact('result.json', result)
    print(json.dumps(result, sort_keys=True), flush=True)
    raise SystemExit('NATIVE_MACHINE_CORE_COMPATIBILITY_BLOCKED')

active_stage = 'setup'
native_activated = False
command_diagnostics = {}

def failure_summary(category):
    # Private logs can contain fixture credentials. Publish only fixed labels,
    # source line numbers, and process status, never log text or exception text.
    diagnostics = {'category': category, 'assertions': [], 'signals': []}
    if command_diagnostics:
        diagnostics['command'] = dict(command_diagnostics)
    log = evidence / 'node-live.log'
    if log.is_file():
        text = log.read_text(errors='replace')
        transport_causes = []
        for line in text.splitlines():
            marker = 'NATIVE_MACHINE_TRANSPORT_CAUSE '
            if marker not in line:
                continue
            encoded = line.split(marker, 1)[1]
            if len(encoded) > 1024:
                continue
            try:
                item = json.loads(encoded)
            except (ValueError, TypeError):
                continue
            fields = {'schema', 'sequence', 'phase', 'endpoint', 'cause', 'context_canceled',
                      'context_deadline', 'error_is_deadline', 'error_is_canceled',
                      'has_deadline', 'deadline_remaining_nanos', 'observed_unix_nanos', 'scope', 'request_elapsed_nanos'}
            if (isinstance(item, dict) and set(item) == fields
                    and item['schema'] == 'txnode-machine-transport-cause/v1'
                    and type(item['sequence']) is int and 1 <= item['sequence'] <= 16
                    and all(type(item[key]) is str for key in ('phase', 'endpoint', 'cause'))
                    and item['phase'] in {'request', 'read_body'} and item['endpoint'] in {'query', 'submit'}
                    and item['cause'] in {'context_deadline', 'context_canceled', 'tls_verification',
                                         'connection_refused', 'connection_reset', 'eof', 'network_timeout', 'other'}
                    and all(type(item[key]) is bool for key in ('context_canceled', 'context_deadline', 'error_is_deadline', 'error_is_canceled', 'has_deadline'))
                    and type(item['deadline_remaining_nanos']) is int
                    and -60_000_000_000 <= item['deadline_remaining_nanos'] <= 60_000_000_000
                    and type(item['observed_unix_nanos']) is int and item['observed_unix_nanos'] > 0):
                if (type(item['scope']) is not str or item['scope'] not in {'startup', 'worker'}
                        or type(item['request_elapsed_nanos']) is not int
                        or not 0 <= item['request_elapsed_nanos'] <= 60_000_000_000):
                    continue
                transport_causes.append(item)
        diagnostics['usage_transport'] = {'observation_limit': 16, 'observations': transport_causes[:16]}
        families = {'/txapi/node/v2/usage/batch/get':'usage_query', '/txapi/node/v2/usage/submit':'usage_submit',
                    '/txapi/node/v1/config':'config', '/txapi/node/v1/users':'users',
                    '/txapi/node/v1/machine/nodes':'discovery', '/txapi/node/v1/handshake':'handshake'}
        timings = {}
        for path, label in families.items():
            events = proxy.event_snapshot()
            values = sorted(min(60_000_000_000, max(0, event['backend_elapsed_nanos']))
                            for event in events if event['kind']=='http' and event.get('path')==path
                            and type(event.get('backend_elapsed_nanos')) is int)
            starts = sum(event['kind']=='http-start' and event.get('path')==path for event in events)
            timings[label] = {'started':min(10000, starts), 'completed':min(10000, len(values)),
                             'over_two_seconds':min(10000, sum(value>2_000_000_000 for value in values)),
                             'max_nanos':max(values, default=0),
                             'median_nanos':values[len(values)//2] if values else 0}
        diagnostics['fixture_backend_timings'] = timings
        config_booleans = {'config_event_received', 'config_event_dispatched', 'config_event_desired_port',
                           'old_listener_open', 'new_listener_open', 'shared_ws_connected'}
        config_fields = config_booleans | {'schema', 'stage', 'code', 'child_applied_port'}
        for line in text.splitlines():
            marker = 'NATIVE_MACHINE_CONFIG_DIAGNOSTIC '
            if marker not in line:continue
            encoded = line.split(marker, 1)[1]
            if len(encoded) > 1024:continue
            try:config_diagnostic = json.loads(encoded)
            except (ValueError, TypeError):continue
            if (isinstance(config_diagnostic, dict) and set(config_diagnostic) == config_fields
                    and config_diagnostic['schema'] == 'txnode-machine-config-diagnostic/v1'
                    and config_diagnostic['stage'] == 'configured'
                    and config_diagnostic['code'] in {'old_stream_remained_open', 'old_stream_close_timeout'}
                    and config_diagnostic['child_applied_port'] == 'unavailable'
                    and all(type(config_diagnostic[field]) is bool for field in config_booleans)):
                events = proxy.event_snapshot()
                config_diagnostic['rest_gate_held'] = not proxy.rest_release.is_set()
                config_diagnostic['config_rest_held'] = any(event['kind'] == 'rest-held' and event['path'] == '/txapi/node/v1/config' for event in events)
                config_diagnostic['users_rest_held'] = any(event['kind'] == 'rest-held' and event['path'] == '/txapi/node/v1/users' for event in events)
                diagnostics['configuration'] = config_diagnostic
        shutdown_booleans = {'terminal_cause_observed', 'terminal_machine_denial', 'context_cancelled',
                             'shared_ws_connected', 'target_listener_open', 'sibling_listener_open'}
        shutdown_fields = shutdown_booleans | {'schema', 'stage', 'code', 'tracked_children', 'completed_children', 'failed_children', 'failure_classes', 'wait_chains'}
        wait_labels = {'machine_children_join', 'machine_discovery', 'machine_child_start', 'machine_status',
                       'startup_recovery', 'startup_setup', 'startup_usage', 'startup_collector', 'startup_replay_page', 'service_run', 'authorization_join', 'authorization_worker', 'native_usage_close',
                       'core_users_read', 'core_http', 'provider_resolve', 'shared_ws_connect', 'kernel_stop', 'worker_wait'}
        for line in text.splitlines():
            marker = 'NATIVE_MACHINE_SHUTDOWN_DIAGNOSTIC '
            if marker not in line:continue
            encoded = line.split(marker, 1)[1]
            if len(encoded) > 4096:continue
            try:shutdown = json.loads(encoded)
            except (ValueError, TypeError):continue
            if (isinstance(shutdown, dict) and set(shutdown) == shutdown_fields
                    and shutdown['schema'] == 'txnode-machine-shutdown-diagnostic/v1'
                    and shutdown['stage'] == 'old-rejected' and shutdown['code'] == 'machine_join_timeout'
                    and all(type(shutdown[field]) is bool for field in shutdown_booleans)
                    and type(shutdown['tracked_children']) is int and 0 <= shutdown['tracked_children'] <= 2
                    and type(shutdown['completed_children']) is int and 0 <= shutdown['completed_children'] <= shutdown['tracked_children']
                    and type(shutdown['failed_children']) is int and 0 <= shutdown['failed_children'] <= 2
                    and isinstance(shutdown['failure_classes'], list) and len(shutdown['failure_classes']) == shutdown['failed_children']
                    and all(type(item) is str and item in FAILURE_CLASSES for item in shutdown['failure_classes'])
                    and isinstance(shutdown['wait_chains'], list) and len(shutdown['wait_chains']) <= 16
                    and all(isinstance(chain, str) and 1 <= len(chain.split('>')) <= 12
                            and all(label in wait_labels for label in chain.split('>')) for chain in shutdown['wait_chains'])):
                rotation_time = rotation.get('completed_monotonic_ns', 0)
                shutdown['completed_http_denial_observed'] = any(
                    event['kind'] == 'http' and event['status'] == 401 and event.get('error_code') == 'NODE_UNAUTHORIZED'
                    and event.get('machine_id') == str(fixture['machine_id']) and event['monotonic_ns'] >= rotation_time
                    for event in proxy.event_snapshot())
                endpoints = {'/txapi/node/v1/config': 'config', '/txapi/node/v1/users': 'users',
                             '/txapi/node/v1/handshake': 'handshake', '/txapi/node/v1/machine/nodes': 'machine_nodes'}
                shutdown['http_401_counts'] = {label: min(10000, sum(
                    event.get('kind') == 'http' and event.get('status') == 401
                    and event.get('machine_id') == str(fixture['machine_id'])
                    and event.get('path') == path and event.get('monotonic_ns', 0) >= rotation_time
                    for event in proxy.event_snapshot())) for path, label in endpoints.items()}
                diagnostics['shutdown'] = shutdown
        for line in text.splitlines():
            marker = 'NATIVE_MACHINE_RECOVERY_DIAGNOSTIC '
            if marker not in line:continue
            encoded = line.split(marker, 1)[1]
            if len(encoded) > 4096:continue
            try:recovery = json.loads(encoded)
            except (ValueError, TypeError):continue
            if valid_recovery(recovery):
                diagnostics['recovery'] = recovery
        source = (node / 'internal/machine/native_core_machine_live_test.go').read_text().splitlines()
        for match in re.finditer(r'native_core_machine_live_test\.go:([0-9]+):', text):
            line = int(match.group(1))
            label = 'assertion'
            if 0 < line <= len(source):
                for function, kind in (
                    ('machineCoreWait', 'readiness'), ('machineCoreDial', 'protocol_dial'),
                    ('machineCoreEcho', 'protocol_echo'), ('machineCoreAlive', 'device_report'),
                    ('machineCoreBarrier', 'barrier'), ('NewChecked', 'orchestrator_create')):
                    if function in source[line - 1]:
                        label = kind
                        break
            item = {'line': line, 'category': label}
            if item not in diagnostics['assertions']:
                diagnostics['assertions'].append(item)
        for needle, label in (
            ('actual machine readiness deadline', 'readiness_timeout'),
            ('machine exited before readiness', 'orchestrator_early_exit'),
            ('connection refused', 'connection_refused'), ('i/o timeout', 'io_timeout'),
            ('context deadline exceeded', 'context_deadline'),
            ('x509:', 'certificate_verification'), ('unknown cipher', 'cipher_configuration'),
            ('unknown kernel', 'kernel_configuration'), ('panic:', 'panic')):
            if needle in text:
                diagnostics['signals'].append(label)
    diagnostics['test_exit_code'] = None if test is None else test.poll()
    result = {'schema': 'txnode-core-machine-result/v1', 'status': 'failed',
              'failed_stage': active_stage, 'core_revision': actual,
              'node_revision': node_revision, 'core_tree': core_tree, 'node_tree': node_tree,
              'core_installation_mode': 'native' if native_activated else 'not_started', 'node_kernel': 'txnode',
              'native_core_installation_admission': False, 'diagnostics': diagnostics}
    if not (evidence / 'result.json').exists():
        artifact('result.json', result)
    print(json.dumps(result, sort_keys=True), flush=True)

def command(name,args,cwd,timeout=180):
    global active_stage
    active_stage=name
    path=evidence/(name+'.log')
    with path.open('xb')as out:
        os.chmod(path,0o600);result=subprocess.run(args,cwd=cwd,env=env,stdout=out,stderr=subprocess.STDOUT,timeout=timeout)
    text=path.read_text()
    command_diagnostics.clear()
    command_diagnostics.update(name=name,exit_code=result.returncode)
    for line in text.splitlines():
        if not line.startswith('NATIVE_MACHINE_FIXTURE_FAILURE '):continue
        try:failure=json.loads(line.split(' ',1)[1])
        except (ValueError,TypeError):continue
        if (isinstance(failure,dict) and set(failure)=={'code','kind','stage'}
                and failure.get('kind') in {'database','json','fixture'}
                and isinstance(failure.get('code'),str)
                and re.fullmatch('[A-Z][A-Z0-9_]{0,180}',failure['code'])
                and isinstance(failure.get('stage'),str)
                and re.fullmatch('(?:bootstrap|trust|seed|account|work|state|unknown|account_(?:vless|vmess)_(?:register|purchase|checkout|work|subject))',failure['stage'])):
            command_diagnostics['fixture']=failure
    if result.returncode or 'fixture' in command_diagnostics:raise RuntimeError('NATIVE_MACHINE_'+name.upper()+'_FAILED')
    return text

def command_json(name,args,cwd):
    text=command(name,args,cwd)
    try:
        value=json.loads(text)
        if not isinstance(value,dict):raise ValueError('object required')
        return value
    except (ValueError,TypeError):
        command_diagnostics['failure_code']='NATIVE_MACHINE_COMMAND_INVALID_JSON'
        raise RuntimeError('NATIVE_MACHINE_COMMAND_INVALID_JSON') from None

def freeport():
    with socket.socket()as connection:connection.bind(('127.0.0.1',0));return connection.getsockname()[1]
ports=set()
while len(ports)<10:ports.add(freeport())
http_port,ws_port,tls_port,port0,port1,new_port,origin_port,foreign_port,provider_port,render_port=sorted(ports)
env.update(NATIVE_MACHINE_NODE_PORT_0=str(port0),NATIVE_MACHINE_NODE_PORT_1=str(port1),NATIVE_MACHINE_NEW_PORT=str(new_port),NATIVE_MACHINE_ORIGIN_PORT=str(origin_port),NATIVE_MACHINE_FOREIGN_PORT=str(foreign_port))
query="SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='txboard_native_machine_test'"
probe=subprocess.check_output([mysql,'--protocol=tcp','-h127.0.0.1','-P'+env['DB_PORT'],'-u'+env['DB_USERNAME'],'-N','-e',query],env=env|{'MYSQL_PWD':env['DB_PASSWORD']},text=True).strip()
if probe!='0':raise SystemExit('NATIVE_MACHINE_NONEMPTY_DATABASE_REFUSED')
command('migrate',[php,'artisan','migrate','--force','--no-interaction'],api)
command('build',['go','test','-c','-race','-o',str(evidence/'native-machine-test'),'./internal/machine'],node,600)
env['CORE_INSTALLATION_MODE']='native'
provider_args=prepare_native(evidence,node,env,command,provider_port,render_port)
trust=command_json('trust',[php,str(scripts/'fixture.php'),'trust'],api)
endpoint='https://127.0.0.1:'+str(tls_port)
env.update(TXBOARD_NATIVE_MACHINE_DIR=str(evidence),TXBOARD_NATIVE_MACHINE_URL=endpoint,
           SSL_CERT_FILE=str(evidence/'ca.pem'),APP_URL=endpoint,
           CORE_BROWSER_ORIGIN=endpoint,CORE_BROWSER_ENABLED='true',CORE_BROWSER_ADMIN_ENABLED='true')
observation=evidence/'native-observations.jsonl';observation.touch(mode=0o600)
proxy=NativeTLSProxy(tls_port,http_port,ws_port,str(evidence/'server.pem'),str(evidence/'server.key'),str(observation))
processes=[];logs=[];test=None

def start(name,args,cwd,process_env=None):
    path=evidence/(name+'.log');out=path.open('xb');os.chmod(path,0o600);logs.append(out)
    process=subprocess.Popen(args,cwd=cwd,env=env if process_env is None else process_env,stdout=out,stderr=subprocess.STDOUT,start_new_session=True);processes.append(process);return process
context=ssl.create_default_context(cafile=str(evidence/'ca.pem'))
def request(path,method,payload,headers):
    body=None if payload is None else json.dumps(payload).encode()
    req=urllib.request.Request(endpoint+path,data=body,method=method,headers={'Content-Type':'application/json'}|headers)
    try:
        with urllib.request.urlopen(req,context=context,timeout=8)as response:return response.status,json.loads(response.read(4<<20))
    except urllib.error.HTTPError as error:return error.code,json.loads(error.read(4<<20))

def barrier(stage,action):
    global active_stage
    active_stage = stage
    deadline=time.monotonic()+25;path=evidence/(stage+'.ready.json')
    while not path.exists():
        if test.poll()is not None:raise RuntimeError('NATIVE_MACHINE_EXITED_BEFORE_'+stage.upper())
        if time.monotonic()>deadline:raise RuntimeError('NATIVE_MACHINE_BARRIER_'+stage.upper()+'_TIMEOUT')
        time.sleep(.03)
    incoming=json.loads(path.read_text());result=action(incoming)
    artifact(stage+'.ack.json',result or {'ok':True})
    return incoming

def state(stage):return command_json(stage+'-state',[php,str(scripts/'fixture.php'),'state'],api)

def admin_operation(operation,fields,key=None):
    headers={'Authorization':bearer,'Origin':endpoint,'X-Core-Admin-Path':'native_machine_admin'}
    if key is not None:headers['Idempotency-Key']=key
    return request('/gateway/v1/core/admin/operations/'+operation,'POST',{'input':fields},headers)

def mutation(node_id,fields):
    status,body=admin_operation('network.nodes.patch',{'node_id':str(node_id)}|fields,str(uuid.uuid4()))
    if status!=200 or body.get('data',{}).get('ok')is not True:raise RuntimeError('NATIVE_MACHINE_ADMIN_MUTATION_FAILED')
    return status

try:
    provider=start('credential-provider',provider_args,node)
    deadline=time.monotonic()+10
    while True:
        if provider.poll() is not None:raise RuntimeError('NATIVE_MACHINE_PROVIDER_START_FAILED')
        try:
            with socket.create_connection(('127.0.0.1',provider_port),timeout=.2):break
        except OSError:pass
        if time.monotonic()>deadline:raise RuntimeError('NATIVE_MACHINE_PROVIDER_READY_TIMEOUT')
        time.sleep(.1)
    fixture=command_json('seed',[php,str(scripts/'fixture.php'),'seed'],api)
    if fixture.get('activation')!={'phase':'open','authority_epoch':'2'}:raise RuntimeError('NATIVE_MACHINE_REAL_ACTIVATION_REQUIRED')
    runtime=fixture.get('runtime',{})
    if (runtime.get('ready') is not True or runtime.get('authority_epoch')!='2'
            or runtime.get('release_id')!=actual
            or re.fullmatch('[a-f0-9]{64}',runtime.get('composition_fingerprint','')) is None):
        raise RuntimeError('NATIVE_MACHINE_APPROVED_CORE_COMPOSITION_REQUIRED')
    native_activated=True
    artifact('fixture.json',fixture)
    env['CORE_INSTALLATION_EPOCH']='2'
    http_env=env|{'PHP_CLI_SERVER_WORKERS':'4'}
    php_profile=json.loads(subprocess.check_output([php,'-r',
        'echo json_encode(["version"=>PHP_VERSION,"opcache_loaded"=>extension_loaded("Zend OPcache"),"opcache_enable"=>ini_get("opcache.enable"),"opcache_enable_cli"=>ini_get("opcache.enable_cli")]);'],env=http_env,text=True))
    artifact('fixture-http-profile.json',{'schema':'txnode-machine-http-profile/v1','php':php_profile,
             'workers':'4','instrumented_clone':True,'accepted_for_S3':False})
    http=start('core-http',[php,'-S','127.0.0.1:'+str(http_port),'-t','public','public/index.php'],api,http_env)
    worker=start('core-workerman',[php,'artisan','ws-server','start','--host=127.0.0.1','--port='+str(ws_port)],api)
    proxy.start()
    deadline=time.monotonic()+10
    while True:
        if http.poll()is not None or worker.poll()is not None:raise RuntimeError('NATIVE_MACHINE_CORE_PROCESS_START_FAILED')
        try:
            with socket.create_connection(('127.0.0.1',ws_port),timeout=.2):pass
            status,_=request('/txapi/node/v1/handshake','POST',{},{} )
            if status==401:break
        except (OSError,urllib.error.URLError,ValueError):pass
        if time.monotonic()>deadline:raise RuntimeError('NATIVE_MACHINE_CORE_READY_TIMEOUT')
        time.sleep(.1)
    fixture=command_json('account',[php,str(scripts/'fixture.php'),'account'],api)
    fixture=render_credentials(evidence,core,env,fixture,command)
    # Replace the private seed metadata only after real Provider-issued material
    # is recipient-rendered; public artifacts never include credentials.
    (evidence/'fixture.json').write_text(json.dumps(fixture));os.chmod(evidence/'fixture.json',0o600)
    status,login=request('/txapi/auth/admin/login','POST',{'email':'native-machine-admin@example.test','password':'SyntheticMachineAdmin2026'},{} )
    bearer=login.get('data',{}).get('auth_data','')
    if status!=200 or not bearer.startswith('Bearer ')or login.get('data',{}).get('is_admin')is not True:raise RuntimeError('NATIVE_MACHINE_ADMIN_LOGIN_FAILED')
    # Negative HTTP authentication uses actual middleware without leaking tokens.
    status,denial=request('/txapi/node/v1/machine/nodes','GET',None,{'Authorization':'Bearer definitely-wrong-local-machine','X-TX-Machine-ID':str(fixture['machine_id'])})
    if status!=401 or denial.get('error',{}).get('code')!='NODE_UNAUTHORIZED':raise RuntimeError('NATIVE_MACHINE_NEGATIVE_AUTH_FAILED')
    test=start('node-live',[str(evidence/'native-machine-test'),'-test.run=^TestNativeCoreMachineLive$','-test.v','-test.timeout=150s'],node)
    stage_states={}
    configuration_gate={}
    def wait_proxy(predicate, code, timeout=10):
        deadline=time.monotonic()+timeout
        while not predicate(proxy.event_snapshot()):
            if test.poll() is not None:raise RuntimeError('NATIVE_MACHINE_TEST_STOPPED_DURING_'+code)
            if time.monotonic()>deadline:raise RuntimeError('NATIVE_MACHINE_'+code+'_TIMEOUT')
            time.sleep(.03)
    def initial(incoming):
        stage_states['initial']=state('initial')
        if not stage_states['initial']['machine_online']or not all(n['ws_online']for n in stage_states['initial']['nodes']):raise RuntimeError('NATIVE_MACHINE_WS_REGISTRY_NOT_ONLINE')
        events=[json.loads(l)for l in observation.read_text().splitlines()]
        upgrades=[e for e in events if e['kind']=='ws-upgrade'and e['status']==101]
        if len(upgrades)!=1 or upgrades[0]['machine_id']!=str(fixture['machine_id'])or upgrades[0]['node_id']is not None:raise RuntimeError('NATIVE_MACHINE_SHARED_SOCKET_REQUIRED')
        proxy.hold_rest()
        configuration_gate['started_monotonic_ns']=time.monotonic_ns()
        wait_proxy(lambda events:any(e['kind']=='rest-held' for e in events),'REAL_REST_BARRIER')
        node_id=str(fixture['nodes'][0]['id'])
        status,snapshot=admin_operation('network.nodes.configuration.get',{'node_id':node_id})
        current=snapshot.get('data',{})
        if status!=200 or current.get('node_id')!=node_id or re.fullmatch('[a-f0-9]{64}',current.get('revision','')) is None:
            raise RuntimeError('NATIVE_MACHINE_CURRENT_NODE_REQUIRED')
        update=json.loads(current['configuration_json'])
        update.update(server_port=new_port,port=str(new_port))
        replace={'node_id':node_id,'expected_revision':current['revision'],'configuration_json':json.dumps(update,separators=(',',':'))}
        key=str(uuid.uuid4())
        status,updated=admin_operation('network.nodes.configuration.replace',replace,key)
        if status!=200 or updated.get('data',{}).get('id')!=node_id:raise RuntimeError('NATIVE_MACHINE_FULL_NODE_CONFIG_MUTATION_FAILED')
        # A lost-response replay must retain the exact owner input and key.
        status,replayed=admin_operation('network.nodes.configuration.replace',replace,key)
        if status!=200 or replayed.get('data')!=updated.get('data'):raise RuntimeError('NATIVE_MACHINE_CONFIG_RECEIPT_REPLAY_FAILED')
        configuration_gate['mutation_completed_monotonic_ns']=time.monotonic_ns()
        return {'ok':True}
    barrier('initial',initial)
    def configured(incoming):
        # New listener is already verified while every config/users REST read
        # waits at the proxy. The source of application is genuine Workerman WS.
        if proxy.rest_release.is_set():raise RuntimeError('NATIVE_MACHINE_WS_ONLY_REST_GATE_NOT_HELD')
        events=proxy.event_snapshot()
        if any(event['kind']=='http' and event['path'] in {'/txapi/node/v1/config','/txapi/node/v1/users'} and event['monotonic_ns']>=configuration_gate['mutation_completed_monotonic_ns'] for event in events):raise RuntimeError('NATIVE_MACHINE_WS_CONFIGURATION_REST_FALLBACK')
        stage_states['configured']=state('configured')
        artifact('ws-only-configuration.json',{'actual_ws_delivery':True,'rest_reads_held':True,'actual_admin_configuration_replace':True,'owner_revision_and_receipt':True})
        proxy.release_rest()
        return {'ok':True}
    barrier('configured',configured)
    transport_start={}
    def transient_start(incoming):
        transport_start['upgrades']=sum(e['kind']=='ws-upgrade' and e['status']==101 and e.get('machine_id')==str(fixture['machine_id']) for e in proxy.event_snapshot())
        proxy.fail_rest(4)
        if proxy.disconnect_machine(fixture['machine_id'])!=1:raise RuntimeError('NATIVE_MACHINE_ONE_SHARED_TUNNEL_REQUIRED')
        return {'ok':True}
    barrier('transient-start',transient_start)
    def transient_recovered(incoming):
        wait_proxy(lambda events:sum(e['kind']=='gateway503' for e in events)==4 and sum(e['kind']=='ws-upgrade' and e['status']==101 and e.get('machine_id')==str(fixture['machine_id']) for e in events)>transport_start['upgrades'],'TRANSIENT_RECONNECT',12)
        stage_states['transient']=state('transient')
        if not stage_states['transient']['machine_online'] or not all(n['ws_online'] for n in stage_states['transient']['nodes']):raise RuntimeError('NATIVE_MACHINE_TRANSIENT_CURRENT_SESSION_REQUIRED')
        proxy.hold_reconnect(fixture['machine_id'])
        return {'ok':True}
    barrier('transient-recovered',transient_recovered)
    def replacement_ready(incoming):
        stage_states['replacement']=state('replacement')
        if not stage_states['replacement']['machine_online'] or not all(n['ws_online'] and n['devices'] for n in stage_states['replacement']['nodes']):raise RuntimeError('NATIVE_MACHINE_SUCCESSOR_DEVICE_FACTS_REQUIRED')
        proxy.release_reconnect()
        return {'ok':True}
    barrier('replacement-ready',replacement_ready)
    def scope_checked(incoming):
        stage_states['scope']=state('scope')
        if not stage_states['scope']['machine_online'] or not all(n['ws_online'] for n in stage_states['scope']['nodes']):raise RuntimeError('NATIVE_MACHINE_SCOPE_TEST_DISTURBED_AUTHORITY')
        mutation(fixture['nodes'][0]['id'],{'enabled':False})
        return {'ok':True}
    barrier('scope-checked',scope_checked)
    def disabled(incoming):
        stage_states['disabled']=state('disabled');rows=stage_states['disabled']['nodes']
        if rows[0]['enabled']or rows[0]['ws_online']or rows[0]['devices']or not rows[1]['ws_online']or not stage_states['disabled']['machine_online']:raise RuntimeError('NATIVE_MACHINE_TARGET_SCOPE_CLEANUP_FAILED')
        mutation(fixture['nodes'][0]['id'],{'enabled':True});return {'ok':True}
    disabled_evidence=barrier('disabled',disabled)
    rotation={}
    def reenabled(incoming):
        stage_states['reenabled']=state('reenabled')
        identity={'machine_id':str(fixture['machine_id'])};key=str(uuid.uuid4())
        status,body=admin_operation('network.machines.token.rotate',identity,key)
        if status!=200 or body.get('data')!={'ok':True}:raise RuntimeError('NATIVE_MACHINE_TOKEN_ROTATION_FAILED')
        rotation['completed_monotonic_ns']=time.monotonic_ns()
        status,credentials=admin_operation('network.machines.credentials.get',identity)
        token=credentials.get('data',{}).get('token','')
        if status!=200 or not isinstance(token,str)or not token or token==fixture['token']:raise RuntimeError('NATIVE_MACHINE_TOKEN_ROTATION_FAILED')
        status,replay=admin_operation('network.machines.token.rotate',identity,key)
        if status!=200 or replay.get('data')!={'ok':True}:raise RuntimeError('NATIVE_MACHINE_ROTATION_RECEIPT_REPLAY_FAILED')
        status,recovered_credentials=admin_operation('network.machines.credentials.get',identity)
        if status!=200 or recovered_credentials.get('data',{}).get('token')!=token:
            raise RuntimeError('NATIVE_MACHINE_ROTATION_RECEIPT_REPLAY_CHANGED_TOKEN')
        return {'token':token}
    barrier('reenabled',reenabled)
    old=barrier('old-rejected',lambda incoming:{'ok':True})
    recovered=barrier('recovered',lambda incoming:{'ok':True})
    if test.wait(timeout=10)!=0:raise RuntimeError('NATIVE_MACHINE_LIVE_TEST_FAILED')
    test_output=(evidence/'node-live.log').read_text()
    if '--- PASS: TestNativeCoreMachineLive ' not in test_output or '--- SKIP: TestNativeCoreMachineLive' in test_output:
        raise RuntimeError('NATIVE_MACHINE_EXACT_TEST_PASS_REQUIRED')
    stage_states['recovered']=state('recovered')
    rows=stage_states['recovered']['batches'];required=disabled_evidence['spools']+old['tails']
    events=[json.loads(l)for l in observation.read_text().splitlines()]
    for spool in required:
        matching=[r for r in rows if str(r['node_id'])==str(spool['node_id']) and str(r['source_epoch'])==spool['source_epoch'] and r['batch_id']==spool['batch_id']]
        if len(matching)!=1 or matching[0]['payload_digest']!=spool['payload_digest'] or matching[0]['status']!='settled':
            raise RuntimeError('NATIVE_MACHINE_ORIGINAL_BATCH_REPLAY_REQUIRED')
        payload=json.loads(matching[0]['canonical_payload'])
        if payload!=spool['payload'] or [e['usage_period_id'] for e in payload['entries']]!=spool['period_ids']:
            raise RuntimeError('NATIVE_MACHINE_REPLAY_ORIGINAL_PERIOD_PAYLOAD_CHANGED')
        frozen=json.loads(matching[0]['frozen_entries'])
        if [e['usage_period_id'] for e in frozen]!=spool['period_ids']:
            raise RuntimeError('NATIVE_MACHINE_REPLAY_FROZEN_PERIOD_CHANGED')
        if any(period!=next(n['initial_period_id'] for n in fixture['nodes'] if n['id']==spool['node_id']) for period in spool['period_ids']):
            raise RuntimeError('NATIVE_MACHINE_REPLAY_ORIGINAL_PERIOD_REQUIRED')
    denials=[e for e in events if e['kind']=='http'and e['status']==401 and e.get('error_code')=='NODE_UNAUTHORIZED'and e.get('machine_id')==str(fixture['machine_id']) and e['monotonic_ns']>=rotation['completed_monotonic_ns']]
    if not denials:raise RuntimeError('NATIVE_MACHINE_COMPLETED_HTTP_DENIAL_REQUIRED')
    if any(e['kind']=='http'and e['path']=='/txapi/node/v1/report'and e['status']==401 for e in events):raise RuntimeError('NATIVE_MACHINE_DENIED_REPORT_ATTEMPT')
    goresult=json.loads((evidence/'machine-live-result.json').read_text())
    # Runtime payloads and SQL snapshots stay private. Public evidence exposes
    # fixed assertion labels, aggregate counts and content/source hashes only.
    artifact('result.json',{'actual_core_workerman_machine':True,'core_revision':actual,'node_revision':node_revision,'core_tree':core_tree,'node_tree':node_tree,'core_installation_mode':'native','core_release_id':runtime['release_id'],'core_composition_fingerprint':runtime['composition_fingerprint'],'canonical_admin_operations':True,'node_kernel':'txnode','actual_transparent_trusted_tls':True,'actual_protocols':['vless','vmess'],'shared_machine_upgrade_count':sum(e['kind']=='ws-upgrade'and e['status']==101 for e in events),'ws_only_configuration_delivery':True,'native_core_installation_admission':True,'transient_disconnect_503_recovery':True,'successor_socket_device_facts':True,'foreign_machine_scope_matrix':True,'membership_withdrawal_proved':True,'machine_token_denial_proved':True,'original_batches_replayed':len(required),'actual_sql_unique_batch_rows':len(required),'independent_full_billing_reconciliation':False,'production_pki_attested':False,'private_go_result_sha256':hashlib.sha256((evidence/'machine-live-result.json').read_bytes()).hexdigest(),'observations_sha256':hashlib.sha256(observation.read_bytes()).hexdigest()})
    print('Native actual Core/Workerman two-node Machine gate passed; public result contains no credentials.')
except Exception:
    failure_summary('runner_failure')
    raise
finally:
    for process in reversed(processes):
        if process.poll()is None:
            try:os.killpg(process.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                process.wait(timeout=3)
    try:proxy.close()
    except RuntimeError:pass
    for output in logs:output.close()

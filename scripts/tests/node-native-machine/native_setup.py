"""Private real Provider provisioning for the Actions-only machine runner."""
import base64
import hashlib
import json
import os


def prepare(directory, node, env, command, port, render_port):
    def openssl(name, *args):
        return command(name, ['openssl', *args], directory)

    openssl('provider-ca', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-keyout', 'ca.key', '-out', 'ca.pem', '-subj', '/CN=machine-fixture-ca')
    for name, role in [('server', 'serverAuth'), ('core', 'clientAuth'), ('node', 'clientAuth')]:
        openssl(name+'-csr', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', name+'.key', '-out', name+'.csr', '-subj', '/CN='+name)
        extension = 'extendedKeyUsage='+role+'\n'
        if role == 'serverAuth':
            extension += 'subjectAltName=DNS:localhost,IP:127.0.0.1\n'
        (directory/(name+'.ext')).write_text(extension)
        openssl(name+'-cert', 'x509', '-req', '-days', '1', '-in', name+'.csr',
                '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial',
                '-out', name+'.pem', '-extfile', name+'.ext')
    for path in directory.glob('*.key'):
        os.chmod(path, 0o600)
    # DER fingerprints bind actual mTLS clients; the Core never selects these.
    fingerprints = {}
    for name in ('core', 'node'):
        import ssl
        der = ssl.PEM_cert_to_DER_cert((directory/(name+'.pem')).read_text())
        fingerprints[name] = hashlib.sha256(der).hexdigest()
    provider = 'https://127.0.0.1:'+str(port)
    render = 'https://127.0.0.1:'+str(render_port)
    seed_file = directory/'authorization.seed'
    with seed_file.open('x') as output:
        os.chmod(seed_file, 0o600)
        output.write(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('='))
        output.flush(); os.fsync(output.fileno())
    env.update({
        'APP_CONFIG_CACHE': str(directory/'config-cache.php'),
        'CORE_CREDENTIAL_PROVIDER_ID': 'primary-provider',
        'CORE_CREDENTIAL_PROVIDER_ENDPOINT': provider+'/operations',
        'CORE_CREDENTIAL_PROVIDER_EPOCH': '1',
        'CORE_CREDENTIAL_PROVIDER_CA_FILE': str(directory/'ca.pem'),
        'CORE_CREDENTIAL_PROVIDER_CERT_FILE': str(directory/'core.pem'),
        'CORE_CREDENTIAL_PROVIDER_KEY_FILE': str(directory/'core.key'),
        'CORE_CREDENTIAL_PROVIDER_PROFILES': 'vless-uuid/v1,vmess-uuid/v1',
        'NATIVE_NODE_AUTHORIZATION_ENABLED': 'true',
        'NATIVE_NODE_AUTHORIZATION_CORE_INSTANCE_ID': '11111111-1111-4111-8111-111111111111',
        'NATIVE_NODE_AUTHORIZATION_KEY_ID': 'machine-provider-key',
        'NATIVE_NODE_AUTHORIZATION_KEY_EPOCH': '1',
        'NATIVE_NODE_AUTHORIZATION_POLICY_VERSION': 'native-provider-authorization/v2',
        'NATIVE_NODE_AUTHORIZATION_PRIVATE_SEED_FILE': str(seed_file),
        'NATIVE_NODE_AUTHORIZATION_LEASE_SECONDS': '120',
        'NATIVE_NODE_AUTHORIZATION_MAX_CLOCK_SKEW_SECONDS': '1',
        'CORE_USAGE_V2_INSTANCE_ID': '11111111-1111-4111-8111-111111111111',
        'NATIVE_PROVIDER_NODE_PROVIDER_ID': 'primary-provider',
        'NATIVE_PROVIDER_NODE_RECIPIENTS_FILE': str(directory/'recipients.json'),
        'NATIVE_MACHINE_RECIPIENT_SHA256': fingerprints['node'],
        'NATIVE_MACHINE_PROVIDER': provider,
        'NATIVE_MACHINE_RENDER': render,
        'NATIVE_SUBSCRIPTION_RENDER_ENDPOINT': render+'/subscription-render',
        'NATIVE_TRAFFIC_RECEIPTS_ENABLED': 'false',
    })
    (directory/'recipients.json').write_text('{}'); os.chmod(directory/'recipients.json', 0o600)
    command('build-provider', ['go', 'build', '-o', str(directory/'credential-provider'),
                             './cmd/credential-provider'], node, 600)
    private = directory/'provider-private'; private.mkdir(mode=0o700)
    return [str(directory/'credential-provider'), '--listen', '127.0.0.1:'+str(port),
            '--store', str(private/'provider.db'), '--provider-id', 'primary-provider', '--epoch', '1',
            '--tls-cert', str(directory/'server.pem'), '--tls-key', str(directory/'server.key'),
            '--client-ca', str(directory/'ca.pem'), '--client-fingerprint', fingerprints['core'],
            '--delivery-trust', str(directory/'trust.json'), '--node-client-fingerprint', fingerprints['node'],
            '--subscription-listen', '127.0.0.1:'+str(render_port),
            '--subscription-tls-cert', str(directory/'server.pem'),
            '--subscription-tls-key', str(directory/'server.key')]


def render_credentials(directory, core, env, fixture, command):
    for index, row in enumerate(fixture['nodes']):
        output = directory/('subscription-'+str(index)+'.json')
        command('render-'+str(index), ['node', str(core/'scripts/native-subscription-client.mjs'),
                '--core-origin', env['TXBOARD_NATIVE_MACHINE_URL'],
                '--provider-origin', env['NATIVE_MACHINE_RENDER'], '--provider-id', 'primary-provider',
                '--subject-id', row['subject_id'], '--bearer-file', str(directory/('user-bearer-'+str(index))),
                '--ca-file', str(directory/'ca.pem'), '--trust-file', str(directory/'trust.json'),
                '--output', str(output)], core, 90)
        connections = json.loads(output.read_text())['connections']
        matching = [item for item in connections if str(item['node']['node_id']) == str(row['id'])]
        if len(matching) != 1:
            raise RuntimeError('NATIVE_MACHINE_RENDERED_NODE_REQUIRED')
        row['uuid'] = matching[0]['uuid']
        os.chmod(output, 0o600)
    return fixture

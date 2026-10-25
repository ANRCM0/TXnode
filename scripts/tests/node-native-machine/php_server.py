"""HTTP fixture capacity for concurrent native Machine children."""

CORE_HTTP_WORKERS = 4
CORE_HTTP_OPTIONS = ['-d', 'opcache.enable=1', '-d', 'opcache.enable_cli=1',
                     '-d', 'opcache.file_update_protection=0', '-d', 'opcache.validate_timestamps=1',
                     '-d', 'opcache.revalidate_freq=0', '-d', 'opcache.jit=0']


def core_http_environment(environment):
    # Keep the two children and their background requests from sharing one
    # serial PHP dev-server queue inside the unchanged recovery page deadline.
    return dict(environment, PHP_CLI_SERVER_WORKERS=str(CORE_HTTP_WORKERS))


def core_http_command(php, port, router, document_root=None):
    # Pin compilation settings independently of the runner's CLI defaults.
    # Source timestamps stay validated; production code and deadlines are unchanged.
    args = [php, *CORE_HTTP_OPTIONS, '-S', '127.0.0.1:' + str(port)]
    if document_root is not None:args += ['-t', document_root]
    return args + [router]

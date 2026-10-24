"""HTTP fixture capacity for concurrent native Machine children."""

CORE_HTTP_WORKERS = 4


def core_http_environment(environment):
    # Keep the two children and their background requests from sharing one
    # serial PHP dev-server queue inside the unchanged recovery page deadline.
    return dict(environment, PHP_CLI_SERVER_WORKERS=str(CORE_HTTP_WORKERS))

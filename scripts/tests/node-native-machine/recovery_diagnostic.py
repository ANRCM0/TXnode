"""Strict public recovery evidence validation; never forwards unknown fields."""

FAILURE_CLASSES = frozenset({
    'other', 'authority_node', 'authority_machine', 'context_canceled',
    'context_deadline', 'provider', 'authorization', 'native_usage',
    'usage_recovery', 'usage_payload_conflict', 'usage_receipt_mismatch', 'usage_transport',
    'usage_http_authority', 'usage_http_validation', 'usage_http_server', 'usage_http_other',
    'filesystem', 'listener', 'usage_protocol', 'reporting',
})


def valid_recovery(recovery):
    booleans = {'context_cancelled', 'shared_ws_connected', 'target_listener_open', 'sibling_listener_open',
                'target_tracked', 'target_done', 'target_backoff', 'owner_terminal',
                'discovery_succeeded', 'discovery_target_present'}
    counts = {'tracked_children', 'completed_children', 'failed_children'}
    fields = booleans | counts | {'schema', 'stage', 'code', 'failure_classes', 'wait_chains', 'target_failure_class'}
    wait_labels = {'machine_children_join', 'machine_discovery', 'machine_child_start', 'machine_status',
                   'startup_recovery', 'startup_setup', 'startup_usage', 'startup_collector', 'startup_replay_page',
                   'service_run', 'authorization_join', 'authorization_worker', 'native_usage_close',
                   'core_users_read', 'core_http', 'provider_resolve', 'shared_ws_connect', 'kernel_stop', 'worker_wait'}
    return (
        isinstance(recovery, dict) and set(recovery) == fields
        and recovery['schema'] == 'txnode-machine-recovery-diagnostic/v1'
        and type(recovery['stage']) is str and type(recovery['code']) is str
        and (recovery['stage'], recovery['code']) in {('recovered', 'fresh_readiness_failed'), ('reenabled', 'member_readiness_failed')}
        and type(recovery['target_failure_class']) is str
        and recovery['target_failure_class'] in FAILURE_CLASSES | {'none'}
        and (not recovery['target_done'] or recovery['target_tracked'])
        and (not recovery['discovery_target_present'] or recovery['discovery_succeeded'])
        and all(type(recovery[field]) is bool for field in booleans)
        and all(type(recovery[field]) is int and 0 <= recovery[field] <= 2 for field in counts)
        and recovery['completed_children'] <= recovery['tracked_children']
        and isinstance(recovery['failure_classes'], list)
        and len(recovery['failure_classes']) == recovery['failed_children']
        and all(type(item) is str and item in FAILURE_CLASSES for item in recovery['failure_classes'])
        and isinstance(recovery['wait_chains'], list) and len(recovery['wait_chains']) <= 16
        and all(type(chain) is str and 1 <= len(chain.split('>')) <= 12
                and all(label in wait_labels for label in chain.split('>')) for chain in recovery['wait_chains'])
    )

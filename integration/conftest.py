import os

import pytest
import sh


@pytest.fixture(scope='session')
def kubectl():
    from sh import kubectl
    return kubectl


@pytest.fixture(scope='function')
def apply_manifest(kubectl):
    to_cleanup = []

    def applier(manifest_path):
        kubectl.apply(filename=manifest_path)
        to_cleanup.append(manifest_path)

    yield applier

    for manifest_path in to_cleanup:
        kubectl.delete(filename=manifest_path)


@pytest.fixture(scope='session')
def get_manifest_path():
    basename = os.path.dirname(__file__)
    path = os.path.join(basename, 'manifests')

    def manifest_getter(manifest_name):
        return os.path.join(path, manifest_name)

    return manifest_getter


@pytest.fixture(scope='function')
def port_forward(kubectl):
    running_port_forwards = []

    def start_port_forward(target, *ports):
        process = kubectl('port-forward', target, *ports, _bg=True)
        running_port_forwards.append(process)

    yield start_port_forward

    for process in running_port_forwards:
        process.kill_group()
        try:
            process.wait()
        except sh.SignalException_SIGKILL:
            pass


@pytest.fixture(scope='session')
def wait_for_pod_ready(kubectl):
    def wait_for_ready(pod_name, **kwargs):
        try:
            kubectl.wait('pod', pod_name, '--for=condition=ready', **kwargs)
        except sh.ErrorReturnCode:
            print(kubectl.describe('pod', pod_name))
            print('-' * 20)
            print(kubectl.logs(pod_name, '--all-containers=true'))
    return wait_for_ready

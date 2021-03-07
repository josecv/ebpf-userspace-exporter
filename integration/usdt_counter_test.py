import time
from concurrent.futures import ThreadPoolExecutor

import pytest
import requests
from prometheus_client.parser import text_string_to_metric_families


@pytest.fixture()
def apply_gunicorn(kubectl, apply_manifest, get_manifest_path,
                   wait_for_pod_ready):
    manifest = get_manifest_path('gunicorn.yaml')
    apply_manifest(manifest)
    wait_for_pod_ready('test-pod', timeout='60s')


def test_pod_goes_ready(apply_gunicorn):
    # If the apply_gunicorn fixture succeeds, the pod will have gone into
    # ready. This test is really just here to make it easy to surface failures
    # in apply_gunicorn
    pass


def test_info_metrics_present(kubectl, apply_gunicorn, port_forward):
    port_forward('test-pod', '8080')
    time.sleep(0.5)
    r = requests.get('http://localhost:8080/metrics')
    assert r.status_code == 200
    found = False
    print(r.text)
    for family in text_string_to_metric_families(r.text):
        if family.name == 'userspace_exporter_enabled_programs':
            found = True
            assert len(family.samples) == 5
            for sample in family.samples:
                assert 'pid' in sample.labels
                assert sample.labels['name'] == 'gc_total'
                assert sample.value == 1.0
    assert found, r.text


def test_counter_is_reported(kubectl, apply_gunicorn, port_forward):
    port_forward('test-pod', '5000')
    port_forward('test-pod', '8080')
    time.sleep(0.5)
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(
            executor.map(lambda _: requests.get('http://localhost:5000/'),
                         range(1000)))
    r = requests.get('http://localhost:8080/metrics')
    assert r.status_code == 200
    found = False
    print(r.text)
    for family in text_string_to_metric_families(r.text):
        if family.name == 'userspace_exporter_gc':
            found = True
            pids = set()
            for sample in family.samples:
                assert 'pid' in sample.labels
                pids.add(sample.labels['pid'])
                assert 'gen' in sample.labels
                assert sample.labels['gen'] in {'0', '1', '2'}
                assert sample.value > 0
            # We expect there to have been garbage collections in all
            # four workers, but maybe not the parent process itself
            assert len(pids) in (4, 5)
    assert found

import time
from concurrent.futures import ThreadPoolExecutor
import redis

import pytest
import requests
from prometheus_client.parser import text_string_to_metric_families


@pytest.fixture()
def apply_redis(kubectl, apply_manifest, get_manifest_path,
                wait_for_pod_ready):
    manifest = get_manifest_path('redis.yaml')
    apply_manifest(manifest)
    wait_for_pod_ready('test-pod', timeout='60s')


def test_info_metrics_present(kubectl, apply_redis, port_forward):
    port_forward('test-pod', '8080')
    time.sleep(0.5)
    r = requests.get('http://localhost:8080/metrics')
    assert r.status_code == 200
    found = False
    print(r.text)
    for family in text_string_to_metric_families(r.text):
        if family.name == 'userspace_exporter_enabled_programs':
            found = True
            assert len(family.samples) == 1
            for sample in family.samples:
                assert 'pid' in sample.labels
                assert sample.labels['name'] == 'malloc_latency'
                assert sample.value == 1.0
    assert found


def test_histogram_is_reported(kubectl, apply_redis, port_forward):
    port_forward('test-pod', '6379')
    port_forward('test-pod', '8080')
    time.sleep(0.5)
    rds = redis.Redis(host='localhost', port=6379, db=0)
    for i in range(1000):
        rds.set(str(i), 'x' * 1000)

    r = requests.get('http://localhost:8080/metrics')
    assert r.status_code == 200
    found = False
    print(r.text)
    for family in text_string_to_metric_families(r.text):
        if family.name == "userspace_exporter_malloc_latency_nanoseconds":
            samples = family.samples
            found = True
            assert len(samples) == 35
            assert len({s.labels['pid'] for s in samples}) == 1
            buckets = [s for s in samples if s.name.endswith('_bucket')]
            counts = [s for s in samples if s.name.endswith('_count')]
            sums = [s for s in samples if s.name.endswith('_sum')]
            assert len(buckets) == 33
            assert len(counts) == 1
            assert len(sums) == 1
            inf_sample = [s for s in buckets if s.labels['le'] == '+Inf'][0]
            inf_value = inf_sample.value
            count_value = counts[0].value
            assert inf_value == count_value
    assert found

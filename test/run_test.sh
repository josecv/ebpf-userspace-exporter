#!/usr/bin/env bash

set -e
cd test
kubectl apply -f manifest.yaml
if ! kubectl wait --timeout=60s --for=condition=ready pod test-pod; then
    kubectl describe pod test-pod
    echo "---------------------------------"
    kubectl logs test-pod -c ebpf-usdt-exporter
    echo "---------------------------------"
    kubectl logs test-pod -c gunicorn
    exit 1
fi

kubectl delete -f manifest.yaml

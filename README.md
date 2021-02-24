# ebpf-userspace-exporter

A Prometheus exporter for custom userspace (e.g. `usdt`, `uprobe`) eBPF metrics.

## Why?

The existing [ebpf_exporter](https://github.com/cloudflare/ebpf_exporter) allows for collection of system-wide eBPF metrics, but does not expose any facilities for exporting metrics from userspace probes.
These metrics can be quite useful in illuminating aspects of a running process; see the [examples](./examples) for some use cases.

Generally, one cannot attach userspace probes to a process in a different namespace, limiting the feasibility of userspace probes in containerized environments.
To work around this, this exporter is designed to run as a [sidecar with namespace sharing](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)

## Usage

To bind to `0.0.0.0:8080` and expose metrics under `/metrics`, run as:

```bash
ebpf-userspace-exporter --listen-address=0.0.0.0:8080 --metrics-path=/metrics --probe-config=/path/to/config.yaml
```

See [configuration](#configuration) for more details on the format for `config.yaml`

If you're running this in a containerized environment, such as kubernetes, you'll have to ensure a few things:

* The exporter runs in the same namespace as the process you wish to monitor.
* The host must have ebpf enabled, and its /lib/modules and /usr/src should be mounted onto the exporter's container
* The exporter must run as privileged or with the `CAP_BPF` capability

In kubernetes the following configuration will do this for an example pod:

```yaml
apiVersion: v1
kind: Pod
metadata:
  creationTimestamp: null
  name: example-pod
spec:
  # Needed so the sidecar and application share the same namespace
  shareProcessNamespace: true
  containers:
  - name: my-application
    # ...
  - name: ebpf-userspace-exporter
    image: docker.pkg.github.com/josecv/ebpf-userspace-exporter/ebpf-userspace-exporter:v0.0.1
    args:
      - -c
      - /opt/config/exporter.yaml
    volumeMounts:
      - name: exporter-config
        mountPath: /opt/config
      - name: modules-host
        mountPath: /lib/modules
      - name: headers-host
        mountPath: /usr/src
    resources: {}
    securityContext:
      privileged: true
  dnsPolicy: ClusterFirst
  volumes:
    - name: exporter-config
      configMap:
        name: my-exporter-config
    - name: modules-host
      hostPath:
        path: /lib/modules
    - name: headers-host
      hostPath:
        path: /usr/src
```

## Configuration

The configuration format is mostly lifted from the `ebpf_exporter`'s [configuration format](https://github.com/cloudflare/ebpf_exporter#configuration) with some changes


### `program`

```
# Program name
name: <program name>
# Metrics attached to the program
[ metrics: metrics ]
# USDT Probes and their target eBPF functions
usdt:
  [ probename: target ... ]
# uprobes and their target eBPF functions
uprobes:
  [ probename: target ... ]
# uretprobes and their target eBPF functions
uretprobes:
  [ probename: target ... ]
# Which running processes to attach the probes to
attachments:
  binary_name: [ binary_name ]
# Cflags are passed to the bcc compiler, useful for preprocessing
cflags:
  [ - -I/include/path
    - -DMACRO_NAME=value ]
# Actual eBPF program code to inject in the kernel
code: [ code ]
```

Note that, since this exporter does not deal with system-level metrics, `kprobes`, `kretprobes`, `tracepoints`, `raw_tracepoints`, and `perf_events` defined inside a `program` will be ignored.

### `attachments`

```
attachments:
  binary_name: [ binary_name ]
```

The `attachments` section details which processes the eBPF program will be attached to.
Currently, this only supports attaching by binary name -- all processes whose binary name equals the one given will be targeted.

*NOTE* This is the binary name as reported by `/proc/${PID}/comm`

# ebpf-userspace-exporter

A Prometheus exporter for custom userspace (e.g. `usdt`, `uprobe`) eBPF metrics.

## Why?

eBPF is a Linux kernel feature that allows sandboxed, user-defined, probes to be attached to a running system.
These probes can be attached to the kernel itself (`kprobes`), but may also be attached to specific userspace processes or libraries (`uprobes`).
This allows for instrumenting a system by, for example, inspecting arguments to system calls, with minimal performance impact.
This makes eBPF uniquely well suited to the task of collecting metrics from a system for aggregation in a time-series database such as Prometheus.

The existing [ebpf_exporter](https://github.com/cloudflare/ebpf_exporter) allows for collection of system-wide metrics via eBPF kernel probes, but does not expose any facilities for exporting metrics from userspace probes.
These metrics can be quite useful in illuminating aspects of a running process; a common use case is profiling the garbage collector in a language runtime.
See the [examples](./examples) for more ideas.

Generally, one cannot attach userspace probes to a process in a different process namespace, limiting the feasibility of userspace probes in containerized environments.
To work around this, this exporter is designed to run as a [sidecar with namespace sharing](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)

## Prerequisites

You will need to install [bcc](https://github.com/iovisor/bcc/blob/master/INSTALL.md#source).
The exporter has been tested with [v0.18.0](https://github.com/iovisor/bcc/releases/tag/v0.18.0).

## Usage

To bind to `0.0.0.0:8080` and expose metrics under `/metrics`, run as:

```bash
ebpf-userspace-exporter --listen-address=0.0.0.0:8080 --metrics-path=/metrics --probe-config=/path/to/config.yaml
```

See [configuration](#configuration) for more details on the format for `config.yaml`

If you're running this in a containerized environment, such as kubernetes, you'll have to ensure a few things:

* The exporter runs in the same process namespace as the process you wish to monitor.
* The host must have ebpf enabled, and its /lib/modules and /usr/src should be mounted onto the exporter's container
* The exporter must run as privileged or with the `CAP_BPF` capability

In kubernetes the following configuration will do this for an example pod:

```yaml
apiVersion: v1
kind: Pod
metadata:
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

The configuration format is mostly lifted from the `ebpf_exporter`'s [configuration format](https://github.com/cloudflare/ebpf_exporter#configuration) with some changes.


### `program`

```yaml
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

```yaml
attachments:
  binary_name: [ binary_name ]
```

The `attachments` section details which processes the eBPF program will be attached to.
Currently, this only supports attaching by binary name -- all processes whose binary name equals the one given will be targeted.

*NOTE* This is the binary name as reported by `/proc/${PID}/comm`

### Examples

The following example will instrument garbage collection for all `gunicorn` processes:

```yaml
programs:
  - name: gc_total
    metrics:
      counters:
        - name: gc_total
          help: Total number of gc events
          table: gc_counts
          labels:
            - name: gen
              size: 8
              decoders:
                - name: uint
    usdt:
      gc__start: trace_gc__start
    attachment:
      binary_name: "gunicorn"
    code: |
      struct gc_event_t {
          u64 gen;
      };

      BPF_HASH(gc_counts, struct gc_event_t);

      int trace_gc__start(struct pt_regs *ctx) {
          struct gc_event_t e = {};
          int gen = 0;
          bpf_usdt_readarg(1, ctx, &gen);
          e.gen = gen;
          gc_counts.increment(e);
          return 0;
      }
```

Resulting metrics:

```
# HELP userspace_exporter_enabled_programs The set of enabled programs
# TYPE userspace_exporter_enabled_programs gauge
userspace_exporter_enabled_programs{name="gc_total",pid="29970"} 1
userspace_exporter_enabled_programs{name="gc_total",pid="29971"} 1
userspace_exporter_enabled_programs{name="gc_total",pid="29972"} 1
userspace_exporter_enabled_programs{name="gc_total",pid="29973"} 1
userspace_exporter_enabled_programs{name="gc_total",pid="29974"} 1
# HELP userspace_exporter_gc_total Total number of gc events
# TYPE userspace_exporter_gc_total counter
userspace_exporter_gc_total{gen="2",pid="29971"} 753
userspace_exporter_gc_total{gen="2",pid="29972"} 764
userspace_exporter_gc_total{gen="2",pid="29973"} 765
userspace_exporter_gc_total{gen="2",pid="29974"} 748
```

## Status

This is a hobby project; it should not be considered production ready.

It is missing a few features that I hope to implement over the coming months:

* The monitored process must be live before the exporter starts, and if it is restarted the exporter will not reattach. In future, it would be nice if it could dynamically attach to any live processes matching the `binary_name`.
* Attaching by binary name isn't very flexible; there are many different ways to find a process of interest -- by its parent process, by its command line, etc
* The original `ebpf-exporter` is able to add a [`tag`](https://github.com/cloudflare/ebpf_exporter#ebpf_exporter_ebpf_programs) label to its info metrics. This is challenging to do here since the USDT APIs don't easily lend themselves to getting a program's tag, but it would be good to at least add it for u(ret)probes.
* Some JVM examples would be fantastic

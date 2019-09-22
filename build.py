#!/bin/python3
# Copyright 2019 Red Hat
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""A script to fetch the required program and assemble a RPM package
"""

from os import listdir
from subprocess import Popen
from typing import Tuple, List
from pathlib import Path
from textwrap import dedent


KUBE_VERSION = "v1.15.3"
KUBE_RELEASE_URL = "https://storage.googleapis.com/kubernetes-release/release"
SRC_DIR = Path("~/.cache/silverkube-sources").expanduser()


def execute(args: List[str], cwd: Path = Path(".")) -> None:
    if Popen(args, cwd=cwd).wait():
        raise RuntimeError(f"failed: {args}")


def clone(url: str, dest: Path) -> Path:
    if (dest / ".git").exists():
        return dest
    execute(["git", "clone", url, str(dest)])
    return dest


def fetch_kube() -> List[Path]:
    def kube_binary(name: str, hash: str) -> Tuple[str, str, str]:
        return (
            name,
            f"{KUBE_RELEASE_URL}/{KUBE_VERSION}/bin/linux/amd64/{name}",
            hash
        )

    paths: List[Path] = []
    for tool, url, hash in (
            kube_binary(
                "kube-apiserver",
                "a2883b4a5e97afd3c6f9fbab3e9c3e22b95b7977ef8a74263f3f8e3f8a"
                "f5344a"
            ), kube_binary(
                "kube-controller-manager",
                "a0c7a5b70d988c9923bb2b3c7d6ce15d5cc65832ea251688043df8ee08"
                "6680f0"
            ), kube_binary(
                "kube-scheduler",
                "130328f89d00afb848a74d3ec8ddaca331a8257a278ec414f3e17089f9"
                "307ce0"
            ), kube_binary(
                "kubelet",
                "dc08c9ad350d0046bc2ec910dcd266bd30cb6e7ef1f9170bb8df455d9d"
                "083d73"
            )):
        path = SRC_DIR / tool
        if path.exists():
            # TODO: check hash
            pass
        else:
            # TODO: check hash
            execute(["curl", "-o", str(path), "-L", url])
        paths.append(path)
    return paths


def fetch_etcd() -> List[Path]:
    url = (
        "https://github.com/etcd-io/etcd/releases/download/"
        "v3.4.0/etcd-v3.4.0-linux-amd64.tar.gz"
    )
    dest = SRC_DIR / Path(url).name
    if not dest.exists():
        execute(["curl", "-o", str(dest), "-L", url])
        # TODO: check hash
    path = SRC_DIR / "etcd-v3.4.0-linux-amd64" / "etcd"
    if not path.exists():
        execute(["tar", "-C", str(SRC_DIR), "-xzf", str(dest),
                 "--no-same-owner"])
    return [path]


def build_crio() -> List[Path]:
    crio = clone("https://github.com/cri-o/cri-o", SRC_DIR / "cri-o")
    # TODO: pin a commit sha
    path = crio / "bin" / "crio"
    if not path.exists():
        execute(["make", "BUILDTAGS='seccomp'"], crio)
    return [path]


def build_conmon() -> List[Path]:
    conmon = clone(
        "https://github.com/containers/conmon", SRC_DIR / "conmon.git")
    # TODO: pin a commit sha
    path = conmon / "bin" / "conmon"
    if not path.exists():
        execute(["make"], conmon)
    return [path]


def build_cni() -> List[Path]:
    cni = clone(
        "https://github.com/containernetworking/plugins", SRC_DIR / "cni")
    if not (cni / "bin" / "portmap").exists():
        # TODO: pin a commit sha
        execute(["git", "checkout", "v0.8.1"], cni)
        execute(["./build_linux.sh"], cni)
    plugins = listdir(str(cni / "bin"))
    return list(map(lambda x: cni / "bin" / x, sorted(plugins)))


def generate_services() -> List[Path]:
    services: List[Path] = []
    for name, args in [(
        "etcd", ["--name silverkube"]
    ), (
        "kube-apiserver", [
            "--etcd-servers=http://localhost:2379",
            "--insecure-bind-address=127.0.0.1",
            "--insecure-port=8043",
            "--service-account-key-file=/var/lib/silverkube/cert.pem",
            "--allow-privileged=true",
            "--v=2"]
    ), (
        "kube-controller-manager", [
            "--master 127.0.0.1:8043",
            "--service-account-private-key-file=/var/lib/silverkube/key.pem"
        ]
    ), (
        "kube-scheduler", ["--kubeconfig /var/lib/silverkube/kubeconfig"]
    ), (
        "kubelet", ["--config=/etc/silverkube/kubelet-config.yaml",
                    "--cni-bin-dir=/usr/libexec/silverkube/cni/",
                    "--cni-conf-dir=/etc/silverkube/net.d",
                    "--container-runtime=remote",
                    "--container-runtime-endpoint="
                    "unix:///var/run/silverkube/crio.sock",
                    "--kubeconfig=/var/lib/silverkube/kubeconfig",
                    "--register-node=true",
                    "--v=2"]
    ), (
        "crio", [
            "--config /etc/silverkube/crio.conf",
        ]
    )]:
        command = "/usr/libexec/silverkube/" + name + " " + " ".join(args)
        path = SRC_DIR / ("silverkube-" + name + ".service")
        path.write_text(dedent(f"""
        [Unit]
        Description=Silverkube {name}
        After=network.target

        [Service]
        SyslogIdentifier=silverkube-{name}
        ExecStart={command}

        [Install]
        WantedBy=multi-user.target
        """)[1:])
        services.append(path)
    return services


def generate_conf() -> List[Path]:
    crio = SRC_DIR / "crio.conf"
    crio.write_text(dedent("""
        [crio]
        log_dir = "/var/log/silverkube/pods"
        [crio.api]
        listen = "/var/run/silverkube/crio.sock"
        host_ip = ""
        stream_address = "127.0.0.1"
        stream_port = "0"
        stream_enable_tls = false
        stream_tls_cert = ""
        stream_tls_key = ""
        stream_tls_ca = ""
        grpc_max_send_msg_size = 16777216
        grpc_max_recv_msg_size = 16777216
        [crio.runtime]
        default_runtime = "runc"
        no_pivot = false
        conmon = "/usr/libexec/silverkube/conmon"
        conmon_cgroup = "pod"
        conmon_env = [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ]
        selinux = true
        seccomp_profile = ""
        apparmor_profile = "crio-default-1.15.1-dev"
        cgroup_manager = "cgroupfs"
        default_capabilities = [
                "CHOWN",
                "DAC_OVERRIDE",
                "FSETID",
                "FOWNER",
                "NET_RAW",
                "SETGID",
                "SETUID",
                "SETPCAP",
                "NET_BIND_SERVICE",
                "SYS_CHROOT",
                "KILL",
        ]
        default_sysctls = [
        ]
        additional_devices = [
        ]
        hooks_dir = [
        ]
        default_mounts = [
        ]
        pids_limit = 1024
        log_size_max = -1
        log_to_journald = false
        container_exits_dir = "/var/run/silverkube/exits"
        container_attach_socket_dir = "/var/run/silverkube"
        bind_mount_prefix = ""
        read_only = false
        log_level = "info"
        uid_mappings = ""
        gid_mappings = ""
        ctr_stop_timeout = 0
        manage_network_ns_lifecycle = false
        [crio.runtime.runtimes.runc]
        runtime_path = ""
        runtime_type = "oci"
        runtime_root = "/run/runc"
        [crio.image]
        default_transport = "docker://"
        global_auth_file = ""
        pause_image = "k8s.gcr.io/pause:3.1"
        pause_image_auth_file = ""
        pause_command = "/pause"
        signature_policy = ""
        image_volumes = "mkdir"
        [crio.network]
        network_dir = "/etc/silverkube/net.d/"
        plugin_dirs = [
          "/usr/libexec/silverkube/cni/",
        ]
        [crio.metrics]
        enable_metrics = false
        metrics_port = 9090
    """))

    kubelet = SRC_DIR / "kubelet-config.yaml"
    kubelet.write_text(dedent("""
      kind: KubeletConfiguration
      apiVersion: kubelet.config.k8s.io/v1beta1
      authentication:
        anonymous:
          enabled: true
      clusterDomain: "silverkube"
      resolvConf: "/etc/resolv.conf"
    """)[1:])
    return [crio, kubelet]


def generate_cni_conf() -> List[Path]:
    bridge = SRC_DIR / "bridge.conflist"
    bridge.write_text(dedent("""
        {
            "cniVersion": "0.3.0",
            "name": "podman",
            "plugins": [
              {
                "type": "bridge",
                "bridge": "sk0",
                "isGateway": true,
                "ipMasq": true,
                "ipam": {
                    "type": "host-local",
                    "subnet": "10.43.0.0/16",
                    "routes": [
                        { "dst": "0.0.0.0/0" }
                    ]
                }
              },
              {
                "type": "portmap",
                "capabilities": {
                  "portMappings": true
                }
              }
            ]
        }
    """)[1:])
    return [bridge]


def generate_systemd_conf() -> List[Path]:
    path = SRC_DIR / "kubelet-cgroups.conf"
    path.write_text(dedent("""
        # Turning on Accounting helps track down performance issues.
        [Manager]
        DefaultCPUAccounting=yes
        DefaultMemoryAccounting=yes
        DefaultBlockIOAccounting=yes
    """))
    return [path]


BuildReq = set([
    "git", "curl", "rpm-build", "make", "btrfs-progs-devel", "which", "runc",
    "containers-common", "device-mapper-devel", "git", "glib2-devel",
    "glibc-devel", "glibc-static", "go", "gpgme-devel", "libassuan-devel",
    "libgpg-error-devel", "libseccomp-devel", "libselinux-devel", "pkgconfig"])

if __name__ == "__main__":
    SRC_DIR.mkdir(exist_ok=True, parents=True)
    execute(["dnf", "install", "-y"] + list(BuildReq))
    bins = fetch_kube() + fetch_etcd() + build_crio() + build_conmon()
    cnis = build_cni()
    systemd_confs = generate_systemd_conf()
    services = generate_services()
    confs = generate_conf()
    cni_confs = generate_cni_conf()
    inputs = confs + cni_confs + systemd_confs + services + bins + cnis

    specfile = [
        "Name: silverkube",
        "Version: 0.0.1",
        "Release: 1%{?dist}",
        "Summary: A kubernetes service for desktop",
        "",
        "License: ASL",
        "URL: https://github.com/podenv/silverkube",
        "",
        "Requires: runc, cri-tools, kubernetes-client, buildah",
        "",
        "Source1: silverkube.py"
    ]
    for idx, source in zip(range(100, 1000), inputs):
        specfile.append(f"Source{idx}: {source.name}")

    specfile.extend([
        "",
        "%description",
        "A kubernetes service for desktop",
        "",
        "%prep",
        "",
        "%build",
        "",
        "%install",
        "install -p -d -m 0700 %{buildroot}/etc/silverkube",
        "install -p -d -m 0700 %{buildroot}/var/run/silverkube",
        "install -p -d -m 0700 %{buildroot}/var/lib/silverkube",
        "install -p -d -m 0700 %{buildroot}/var/log/silverkube",
        "install -p -D -m 0755 %{SOURCE1} %{buildroot}/bin/silverkube",
        "",
    ])

    def sd(mode: str, path: str, srcs: List[Path]) -> List[Tuple[str, str]]:
        return list(map(lambda x: (mode, path + "/" + x.name), srcs))

    for idx, (mode, dest) in zip(
            range(100, 1000),
            sd("644", "etc/silverkube", confs) +
            sd("644", "etc/silverkube/net.d", cni_confs) +
            sd("644", "etc/systemd/system.conf.d", systemd_confs) +
            sd("644", "%{_unitdir}", services) +
            sd("755", "usr/libexec/silverkube", bins) +
            sd("755", "usr/libexec/silverkube/cni", cnis)):
        specfile.append(
            "install -p -D -m 0%s %%{SOURCE%d} %%{buildroot}/%s" % (
                mode, idx, dest))

    for phase in ("post", "preun", "postun"):
        specfile.append("")
        specfile.append("%" + phase)
        for service in services:
            specfile.append(f"%systemd_{phase} {service.name}")
    specfile.extend([
        "", "%files",
        "%config(noreplace) /etc/systemd/system.conf.d/kubelet-cgroups.conf",
        "%config(noreplace) /etc/silverkube/crio.conf",
        "%config(noreplace) /etc/silverkube/kubelet-config.yaml",
        "%config(noreplace) /etc/silverkube/net.d/bridge.conflist",
        "%dir /etc/silverkube",
        "%dir /var/lib/silverkube",
        "%dir /var/run/silverkube",
        "%dir /var/log/silverkube",
        "/bin/silverkube",
        "/usr/libexec/silverkube",
        "%{_unitdir}/silverkube-*",
        "", "%changelog",
        "* Sat Sep 21 2019 Tristan Cacqueray <tdecacqu@redhat.com>",
        "- Initial packaging"
    ])
    Path("silverkube.spec").write_text("\n".join(specfile))

    for local in inputs + [Path("silverkube.py")]:
        dest = SRC_DIR / local.name
        if not dest.exists():
            execute(["ln", "-sf", local.resolve(), str(dest)])

    execute(["rpmbuild", "--define", "_sourcedir %s" % SRC_DIR.resolve(),
             "--define", "_topdir %s" % Path('rpmbuild').resolve(),
             "-ba", "silverkube.spec"])

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

from os import listdir
from subprocess import Popen
from typing import Tuple, List
from pathlib import Path
from textwrap import dedent


KUBE_VERSION = "v1.15.3"
KUBE_RELEASE_URL = "https://storage.googleapis.com/kubernetes-release/release"
CONF_DIR = Path("/var/lib/k2s")


def execute(args: List[str], cwd: Path = Path(".")) -> None:
    if Popen(args, cwd=cwd).wait():
        raise RuntimeError(f"failed: {args}")


def fetch_binaries() -> List[str]:
    def kube_binary(name, hash) -> Tuple[str, str, str]:
        return (
            name,
            f"{KUBE_RELEASE_URL}/{KUBE_VERSION}/bin/linux/amd64/{name}",
            hash
        )

    binaries: List[str] = []
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
        if Path(tool).exists():
            # TODO: check hash
            pass
        else:
            raise NotImplementedError("Download is not implemented")
        binaries.append(tool)
    # TODO: depack etcd
    binaries.append("etcd")
    return binaries


def build_crio() -> List[str]:
    if not (Path("cri-o") / ".git").exists():
        execute(["git", "clone", "https://github.com/cri-o/cri-o"])
    if not (Path("cri-o") / "bin" / "crio").exists():
        execute(["sudo", "yum", "install", "-y", "btrfs-progs-devel",
                 "containers-common",
                 "device-mapper-devel",
                 "git",
                 "glib2-devel",
                 "glibc-devel",
                 "glibc-static",
                 "go",
                 "gpgme-devel",
                 "libassuan-devel",
                 "libgpg-error-devel",
                 "libseccomp-devel",
                 "libselinux-devel",
                 "pkgconfig",
                 "runc"])
        execute(["make", "BUILDTAGS='seccomp apparmor'"], Path("cri-o"))
    if not Path("crio").exists():
        execute(["cp", str(Path("cri-o") / "bin" / "crio"), "."])
    return ["crio"]


def build_cni() -> List[str]:
    if not (Path("plugins") / ".git").exists():
        execute(["git", "clone",
                 "https://github.com/containernetworking/plugins"])
    if not (Path("plugins") / "bin" / "portmap").exists():
        execute(["git", "checkout", "v0.8.1"], Path("plugins"))
        execute(["./build_linux.sh"], Path("plugins"))
    plugins = listdir("plugins/bin")
    for plugin in plugins:
        if not Path(plugin).exists():
            execute(["cp", str(Path("plugins") / "bin" / plugin), "."])
    return plugins


def build_conmon() -> List[str]:
    if not (Path("conmon.git") / ".git").exists():
        execute(["git", "clone",
                 "https://github.com/containers/conmon",
                 "conmon.git"])
    if not (Path("conmon.git") / "bin" / "conmon").exists():
        execute(["make"], Path("conmon.git"))
    if not Path("conmon").exists():
        execute(["cp", str(Path("conmon.git") / "bin" / "conmon"), "."])
    return ["conmon"]


def generate_services() -> List[str]:
    services: List[str] = []
    for name, args in [(
        "etcd", ["--name silverkube"]
    ), (
        "kube-apiserver", [
            "--etcd-servers=http://localhost:2379",
            "--insecure-bind-address=127.0.0.1",
            "--insecure-port=8043",
            "--service-account-key-file=/var/lib/silverkube/cert.pem",
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
        Path("silverkube-" + name + ".service").write_text(dedent(f"""
        [Unit]
        Description=Silverkube {name}
        After=network.target

        [Service]
        SyslogIdentifier=silverkube-{name}
        ExecStart={command}

        [Install]
        WantedBy=multi-user.target
        """)[1:])
        services.append(name)
    return services


def generate_conf():
    Path("crio.conf").write_text(dedent("""
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
    Path("net.d").mkdir(exist_ok=True)
    Path("net.d/bridge.conflist").write_text(dedent("""
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
    Path("kubelet-config.yaml").write_text(dedent("""
      kind: KubeletConfiguration
      apiVersion: kubelet.config.k8s.io/v1beta1
      authentication:
        anonymous:
          enabled: true
      clusterDomain: "silverkube"
      resolvConf: "/etc/resolv.conf"
    """)[1:])
    return ["crio.conf", "net.d/bridge.conflist", "kubelet-config.yaml"]


if __name__ == "__main__":
    bins = fetch_binaries() + build_crio() + build_conmon()
    cnis = build_cni()
    services = generate_services()
    confs = generate_conf()

    specfile = [
        "Name: silverkube",
        "Version: 0.0.1",
        "Release: 1%{?dist}",
        "Summary: A kubernetes service for desktop",
        "",
        "License: ASL",
        "URL: https://github.com/TristanCacqueray/silverkube",
        "",
        "Requires: runc, conmon, cri-tools, kubernetes-client",
        "",
        "Source1: silverkube.py",
        "# kube binaries",
    ]
    for idx, source in zip(range(50, 100), confs):
        specfile.append(f"Source{idx}: {source}")

    for idx, source in zip(range(100, 200), bins):
        specfile.append(f"Source{idx}: {source}")

    specfile.extend(["", "# cni binaries"])
    for idx, source in zip(range(200, 300), cnis):
        specfile.append(f"Source{idx}: {source}")

    specfile.extend(["", "# service files"])
    for idx, source in zip(range(300, 400), services):
        specfile.append(f"Source{idx}: silverkube-{source}.service")

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
        "# Create state directories",
        "install -p -d -m 0700 %{buildroot}/etc/silverkube",
        "install -p -d -m 0700 %{buildroot}/var/lib/silverkube",
        "install -p -d -m 0700 %{buildroot}/var/log/silverkube",
        "",
        "# Install conf",
        "",
    ])
    for idx, conf in zip(range(50, 100), confs):
        specfile.append(
            ("install -p -D -m 0644 %%{SOURCE%d} "
             "%%{buildroot}/etc/silverkube/%s") % (
                 idx, conf))
    specfile.extend([
        "# Install binaries",
        "install -p -D -m 0755 %{SOURCE1} %{buildroot}/bin/silverkube"
    ])
    for idx, bin in zip(range(100, 200), bins):
        specfile.append(
            ("install -p -D -m 0755 %%{SOURCE%d} "
             "%%{buildroot}/usr/libexec/silverkube/%s") % (
                idx, bin))
    for idx, bin in zip(range(200, 300), cnis):
        specfile.append(
            ("install -p -D -m 0755 %%{SOURCE%d} "
             "%%{buildroot}/usr/libexec/silverkube/cni/%s") % (
                idx, bin))
    specfile.extend([
        "",
        "# Install spec files"
    ])
    for idx, service in zip(range(300, 400), services):
        specfile.append(
            ("install -p -D -m 0644 %%{SOURCE%d} "
             "%%{buildroot}/%%{_unitdir}/silverkube-%s.service") % (
                 idx, service))

    specfile.extend("")
    for phase in ("post", "preun", "postun"):
        specfile.append("%" + phase)
        for service in services:
            specfile.append("%%systemd_%s silverkube-%s.service" % (
                phase, service
            ))
        specfile.append("")
    specfile.extend([
        "",
        "%files",
        "%config(noreplace) /etc/silverkube/crio.conf",
        "%config(noreplace) /etc/silverkube/net.d/bridge.conflist",
        "%dir /etc/silverkube",
        "%dir /var/lib/silverkube",
        "%dir /var/run/silverkube",
        "%dir /var/log/silverkube",
        "/bin/silverkube"
        "/usr/libexec/silverkube",
        "%{_unitdir}/silverkube-*"
        "",
        "%changelog",
        "* Sat Sep 21 2019 Tristan Cacqueray <tdecacqu@redhat.com>",
        "- Initial packaging"
    ])
    Path("silverkube.spec").write_text("\n".join(specfile))
#    execute(["rpmbuild", "--define", "_sourcedir %s" % Path('.').resolve(),
#             "-ba", "silverkube.spec"])

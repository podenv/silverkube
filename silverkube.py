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

"""A script to start the services
"""

from base64 import b64encode, b64decode
from json import dumps as json_dumps
from os import environ, getuid, chown
from subprocess import Popen, PIPE
from time import sleep
from typing import List, Tuple, Optional
from sys import argv
from pathlib import Path
from textwrap import dedent

USERNETES = getuid() > 0
RKJOIN = Path("~/.local/bin/rootless-join").expanduser()

if USERNETES:
    # User Paths
    STORAGE = Path("~/.local/share/silverkube/storage").expanduser()
    CRIO_RUNROOT = Path("~/.local/share/silverkube/runroot").expanduser()
    CONF = Path("~/.config/silverkube").expanduser()
    LOCAL = Path("~/.local/silverkube").expanduser()
    RUN = Path(environ["XDG_RUNTIME_DIR"]) / "silverkube"
    SYSTEMD = Path("~/.config/systemd/user").expanduser()
    SYSTEMCTL = ["systemctl", "--user"]
    NSJOIN = [str(RKJOIN)]
    UIDMAPPING = ",".join([
        "1000:0:1",
        "0:1:1000",
        "1001:1001:%s" % (2**16 - 1001)
    ])
else:
    # Admin Paths
    CONF = Path("/etc/silverkube")
    STORAGE = Path("/var/lib/silverkube") / "storage"
    CRIO_RUNROOT = Path("/var/lib/silverkube") / "runroot"
    LOCAL = Path("/var/lib/silverkube") / "local"
    RUN = Path("/run/silverkube")
    SYSTEMD = Path("/etc/systemd/system")
    SYSTEMCTL = ["systemctl"]
    NSJOIN = []
    UIDMAPPING = ""

VERBOSE = "0"
LOGS = RUN / "logs"
RKINIT = CONF / "rkinit"
PKI = CONF / "pki"
KUBECONFIG = CONF / "kubeconfig"
CRIOSOCKPATH = f"{RUN}/crio.sock"
CRIOSOCK = f"unix://{CRIOSOCKPATH}"

ca = "--cacert " + str(PKI / "ca.pem")
etcd_ca = (
    f"{ca} -E " + str(PKI / "etcd-cert.pem") +
    " --key " + str(PKI / "etcd-key.pem"))
api_ca = (
    f"{ca}  -E " + str(PKI / "sa-cert.pem") +
    " --key " + str(PKI / "sa-key.pem"))

KUBE_GATEWAY = "10.43.0.1"
PODS_CIDR = "10.43.0.0/16"
KUBE_ENDPOINT = "10.42.0.1"
SERVICES_CIDR = "10.42.0.0/16"

# Types
ServiceName = str
Command = str
ExpectedOutput = str
Enabled = bool
Check = Tuple[Command, ExpectedOutput]
File = Tuple[Path, str]
Service = Tuple[ServiceName, Enabled, List[Command], List[File], Optional[Check]]

# Services
Services: List[Service] = [
    ("rootlesskit", USERNETES,
     [
         "--state-dir", str(RUN / "rk"),
         "--net=slirp4netns --mtu=65520 --disable-host-loopback",
         "--slirp4netns-sandbox=true --slirp4netns-seccomp=true",
         "--port-driver=builtin",
         "--copy-up=/etc --copy-up=/run --copy-up=/var/lib",
         "--copy-up=/opt",  # --copy-up=/sys",
         "--pidns",
         str(RKINIT)
     ]
     , [(RKJOIN, dedent("""
          #!/bin/sh
          NS="${XDG_RUNTIME_DIR}/silverkube/rk/child_pid"
          while ! test -f $NS; do
            echo "$NS: ENOENT"
            sleep .5;
          done
          while ! /bin/nsenter -U --preserve-credential -m -t $(cat $NS) \
            test -f ${XDG_RUNTIME_DIR}/silverkube/rk/ready; do
            echo "rootless not ready"
            sleep .5;
          done
          export _CRIO_ROOTLESS=1
          exec /bin/nsenter -U --preserve-credential -n -m -p -t $(cat $NS) \
            --wd=$(pwd) $*
     """)), (RKINIT, dedent(f"""
          #!/bin/sh
          mkdir -p /opt/cni/bin

          # Sliprnet remount /sys which prevent selinux from being detected
          # This is not actually working...
          # umount -l /sys

          mount --bind /usr/libexec/silverkube/cni /opt/cni/bin
          mount --bind {CONF}/net.d/ /etc/cni/net.d/
          for dst in /var/lib/kubelet /var/lib/cni /var/log /var/lib/crio; do
            src={RUN}/$(basename dst)
            mkdir -p $src
            mount --bind $src $dst
          done
          rm -f /run/xtables.lock
          touch $XDG_RUNTIME_DIR/silverkube/rk/ready
          exec /bin/sleep infinity
     """))]
     , None),

    ("crio", True,
     [
         "--config", str(CONF / "crio.conf")
     ]
     , [(CONF / "crio.conf", dedent(f"""
          [crio]
          log_dir = "{LOGS}/crio-pods"
          root = "{STORAGE}"
          runroot = "{CRIO_RUNROOT}"
          storage_driver = "vfs"
          storage_option = []
          version_file = "{RUN}/crio-version"

          [crio.api]
          listen = "{CRIOSOCKPATH}"
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
          selinux = {'false' if USERNETES else 'false'}
          seccomp_profile = ""
          apparmor_profile = ""
          cgroup_manager = "cgroupfs"
          default_sysctls = []
          additional_devices = [
            "/dev/tty1:/dev/tty1:rwm",
            "/dev/fb0:/dev/fb0:rwm",
            "/dev/dri/card0:/dev/dri/card0:rwm",
            "/dev/input/event0:/dev/input/event0:rwm",
            "/dev/input/event1:/dev/input/event1:rwm",
            "/dev/input/event2:/dev/input/event2:rwm",
            "/dev/input/mice:/dev/input/mice:rwm",
            "/dev/input/mouse0:/dev/input/mouse0:rwm",
            "/dev/input/mouse1:/dev/input/mouse1:rwm",
          ]
          hooks_dir = []
          pids_limit = 1024
          log_size_max = -1
          log_to_journald = false
          container_exits_dir = "{RUN}/crio/exits"
          container_attach_socket_dir = "{RUN}/crio/sockets"
          bind_mount_prefix = ""
          read_only = false
          log_level = "info"
          uid_mappings = "{UIDMAPPING}"
          gid_mappings = "{UIDMAPPING}"
          ctr_stop_timeout = 0
          pinns_path = "/usr/libexec/silverkube/pinns"

          [crio.runtime.runtimes.runc]
          runtime_path = ""
          runtime_type = "oci"
          runtime_root = "{RUN}/runc"

          [crio.image]
          default_transport = "docker://"
          global_auth_file = ""
          pause_image = "k8s.gcr.io/pause:3.1"
          pause_image_auth_file = ""
          pause_command = "/pause"
          signature_policy = ""
          image_volumes = "mkdir"

          [crio.network]
          network_dir = "{CONF}/net.d/"
          plugin_dirs = ["/usr/libexec/silverkube/cni/"]

          [crio.metrics]
          enable_metrics = false
          metrics_port = 9090
     """)), (CONF / "net.d" / "loopback.conf", dedent("""
          {
                "cniVersion": "0.3.0",
                "type": "loopback"
          }
     """)), (CONF / "net.d" / "bridge.conf", dedent("""
          {
              "cniVersion": "0.3.0",
              "name": "sk0",
              "type": "bridge",
              "bridge": "sk0",
              "isGateway": true,
              "ipMasq": true,
              "hairpinMode": true,
              "ipam": {
                  "type": "host-local",
                  "subnet": "%s",
                  "routes": [
                      { "dst": "0.0.0.0/0" }
                  ]
              }
          }
     """ % PODS_CIDR))]
     , (f"/usr/libexec/silverkube/crictl --runtime-endpoint {CRIOSOCK} version",
        "RuntimeName:  cri-o")),

    ("etcd", True,
     [
         "--name silverkube", "--data-dir", str(RUN / "etcd"),
         "--key-file", str(PKI / "etcd-key.pem"),
         "--cert-file", str(PKI / "etcd-cert.pem"),
         "--trusted-ca-file", str(PKI / "ca.pem"),
         "--advertise-client-urls https://127.0.0.1:2379",
         "--listen-client-urls https://127.0.0.1:2379",
     ]
     , [], (f"curl {etcd_ca} https://localhost:2379/version", "etcdcluste")),

    ("kube-apiserver", True,
     [
         "--client-ca-file", str(PKI / "ca.pem"),
         "--etcd-cafile", str(PKI / "ca.pem"),
         "--etcd-certfile", str(PKI / "etcd-cert.pem"),
         "--etcd-keyfile", str(PKI / "etcd-key.pem"),
         "--etcd-servers https://localhost:2379",
         "--tls-cert-file", str(PKI / "api-cert.pem"),
         "--tls-private-key-file", str(PKI / "api-key.pem"),
         "--bind-address 0.0.0.0",
         "--secure-port 8043",
         "--service-account-key-file", str(PKI / "sa-cert.pem"),
         "--anonymous-auth=False",
         # disable abac for now
         # "--authorization-mode=Node,RBAC,ABAC",
         # "--authorization-policy-file", str(CONF / "abac.json"),
         "--kubelet-client-certificate",
         str(PKI / "kubelet-cert.pem"),
         "--kubelet-client-key",
         str(PKI / "kubelet-key.pem"),
         "--allow-privileged=true",
         "--service-cluster-ip-range", SERVICES_CIDR,
         # disable psp for now
         # "--enable-admission-plugins ",
         # "PodSecurityPolicy",
         f"--v={VERBOSE}",
     ]
     , [(CONF / "abac.json", "\n".join(map(
         json_dumps, [
             dict(apiVersion="abac.authorization.kubernetes.io/v1beta1",
                  kind="Policy",
                  spec=dict(user="localhost",
                            namespace="*",
                            resource="*",
                            apiGroup="*"))])))]
     , (f"curl {api_ca} https://localhost:8043/api", "APIVersions")),

    ("kube-controller-manager", True,
     [
         "--bind-address 127.0.0.1",
         "--cluster-cidr", PODS_CIDR,
         "--service-cluster-ip-range", SERVICES_CIDR,
         "--cluster-signing-cert-file", str(PKI / "ca.pem"),
         "--cluster-signing-key-file", str(PKI / "cakey.pem"),
         "--kubeconfig", str(KUBECONFIG),
         "--tls-cert-file", str(PKI / "controller-cert.pem"),
         "--tls-private-key-file",
         str(PKI / "controller-key.pem"),
         "--service-account-private-key-file",
         str(PKI / "sa-key.pem"),
         "--root-ca-file", str(PKI / "ca.pem"),
         "--leader-elect=false",
         "--use-service-account-credentials=true",
         f"--v={VERBOSE}",
     ]
     , [], None),

    ("kube-scheduler", True,
     [
         "--kubeconfig", str(KUBECONFIG),
         f"--v={VERBOSE}",
     ]
     , [], ("/bin/kubectl get componentstatuses", "Healthy")),

    ("kube-proxy", True,
     [
         "--config", str(CONF / "kube-proxy.yaml"),
         f"--v={VERBOSE}",
     ]
     , [(CONF / "kube-proxy.yaml", dedent("""
          kind: KubeProxyConfiguration
          apiVersion: kubeproxy.config.k8s.io/v1alpha1
          clientConnection:
            kubeconfig: "%s"
          mode: "iptables"
          clusterCIDR: "%s"
     """) % (str(KUBECONFIG), SERVICES_CIDR))]
     , None),

    ("kubelet", True,
     [
         "--config", str(CONF / "kubelet-config.yaml"),
         "--root-dir", str(LOCAL / "kubelet"),
         "--log-dir", str(RUN / "logs" / "kubelet-logs"),
         "--cni-bin-dir=/usr/libexec/silverkube/cni/",
         "--cni-conf-dir", str(CONF / "net.d"),
         "--tls-cert-file", str(PKI / "kubelet-cert.pem"),
         "--tls-private-key-file", str(PKI / "kubelet-key.pem"),
         "--anonymous-auth=false",
         "--client-ca-file", str(PKI / "ca.pem"),
         "--container-runtime=remote",
         "--container-runtime-endpoint", str(CRIOSOCK),
         "--kubeconfig", str(KUBECONFIG),
         "--register-node=true",
         f"--v={VERBOSE}",
     ] + ([
         "--feature-gates",
         "DevicePlugins=false,SupportNoneCgroupDriver=true",
         "--cgroup-driver=none --cgroups-per-qos=false",
         "--enforce-node-allocatable=''",
         "--register-node=true",
        ] if USERNETES else [])
     , [(CONF / "kubelet-config.yaml", dedent("""
          kind: KubeletConfiguration
          apiVersion: kubelet.config.k8s.io/v1beta1
          authentication:
            anonymous:
              enabled: true
            webhook:
              enabled: true
            x509:
              clientCAFile: "%s"
          tlsCertFile: "%s"
          tlsPrivateKeyFile: "%s"
          authorization:
            mode: Webhook
          clusterDomain: "cluster.local"
          clusterDNS:
            - "%s"
          podCIDR: "%s"
          ImageMinimumGCAge: 100000m
          HighThresholdPercent: 100
          LowThresholdPercent: 0
     """) % (str(PKI / "ca.pem"),
             str(PKI / "kubelet-cert.pem"),
             str(PKI / "kubelet-key.pem"),
             KUBE_GATEWAY, PODS_CIDR))] + ([] if USERNETES else [
                 (Path("/etc/systemd/system.conf.d/kubelet-cgroups.conf"), dedent("""
          # Turning on Accounting helps track down performance issues.
          [Manager]
          DefaultCPUAccounting=yes
          DefaultMemoryAccounting=yes
          DefaultBlockIOAccounting=yes
                 """))])
     , ("/bin/kubectl get nodes", "Ready")),

    ("coredns", True, ["--conf", str(CONF / "Corefile")]
     , [(CONF / "Corefile", dedent("""
          .:53 {
              kubernetes cluster.local silverkube {
                kubeconfig %s local
                pods insecure
              }
              forward . /etc/resolv.conf
              cache 30
          }
     """ % str(CONF / "kubeconfig")))]
     , None),
    # coredns check requires bridge (f"dig @{KUBE_GATEWAY} ns.dns.cluster.local +noall +answer", "10.42.0.1")),
]
HostPaths = [
    dict(name="xorg"),
    dict(name="wayland"),
    dict(name="dbus"),
    dict(name="pulseaudio"),
]


# Utility procedures
def execute(args: List[str]) -> None:
    if Popen(args).wait():
        raise RuntimeError(f"Fail: {args}")


def pread(args: List[str]) -> Tuple[str, str]:
    p = Popen(args, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate()
    return stdout.decode('utf-8'), stderr.decode('utf-8')


def b64(data: str) -> str:
    return b64encode(data.encode('utf-8')).decode('utf-8')


def generate_cert(name) -> None:
    key = (PKI / (name + "-key.pem"))
    req = (PKI / (name + "-cert.req"))
    crt = (PKI / (name + "-cert.pem"))
    if not key.exists():
        execute(
            ["openssl", "genrsa", "-out", str(key), "2048"])
    if not req.exists():
        execute(
            ["openssl", "req", "-new", "-subj",
             "/C=FR/O=SoftwareFactory/CN=localhost",
             "-extensions", "v3_req", "-config", str(PKI / "ca.cnf"),
             "-key", str(key), "-out", str(req)])
    if not crt.exists():
        execute(
            ["openssl", "x509", "-req", "-days", "365", "-sha256",
             "-extensions", "v3_req", "-extfile", str(PKI / "ca.cnf"),
             "-CA", str(PKI / "ca.pem"), "-CAkey", str(PKI / "cakey.pem"),
             "-CAserial", str(PKI / "ca.srl"),
             "-in", str(req), "-out", str(crt)])


def generate_certs() -> str:
    PKI.mkdir(parents=True, exist_ok=True)
    (PKI / "ca.cnf").write_text(dedent("""
      [req]
      req_extensions = v3_req
      distinguished_name = req_distinguished_name

      [ req_distinguished_name ]
      commonName_default = localhost

      [ v3_req ]
      subjectAltName=@alt_names

      [alt_names]
      DNS.1 = localhost
      IP.1 = %s
      IP.2 = %s
    """ % (KUBE_ENDPOINT, KUBE_GATEWAY)))
    (PKI / "ca.srl").write_text("00\n")
    if not (PKI / "cakey.pem").exists():
        execute(["openssl", "req", "-nodes", "-days", "3650", "-new",
                 "-x509", "-subj", "/C=FR/O=SilverKube/OU=42",
                 "-keyout", str(PKI / "cakey.pem"),
                 "-out", str(PKI / "ca.pem")])
    for i in ("etcd", "sa", "api", "kubelet", "controller", "crio"):
        generate_cert(i)
    return (PKI / "ca.pem").read_text()


def generate_kubeconfig(ca: str) -> None:
    KUBECONFIG.write_text(dedent("""
        apiVersion: v1
        kind: Config
        preferences: {}
        clusters:
        - cluster:
            server: https://localhost:8043
            certificate-authority-data: %s
          name: local
        users:
        - name: local
          user:
            client-key-data: %s
            client-certificate-data: %s
        contexts:
        - context:
            cluster: local
            user: local
          name: local
        current-context: local
    """)[1:] % (ca, b64((PKI / "sa-key.pem").read_text()),
                b64((PKI / "sa-cert.pem").read_text())))


def generate_policy() -> None:
    (CONF / "policy.yaml").write_text(dedent("""
        apiVersion: policy/v1beta1
        kind: PodSecurityPolicy
        metadata:
          name: silverkube-psp-privileged
          namespace: silverkube
        spec:
          privileged: false
          allowPrivilegeEscalation: true
          allowedCapabilities:
            - CAP_SYS_ADMIN
          readOnlyRootFilesystem: true
          volumes:
            - 'configMap'
            - 'emptyDir'
            - 'secret'
            - 'hostPath'
          allowedHostPaths:
            - pathPrefix: '/dev/dri'
            - pathPrefix: '/dev/fb0'
            - pathPrefix: '/dev/input'
            - pathPrefix: '/dev/snd'
            - pathPrefix: '/dev/tty0'
            - pathPrefix: '/dev/tty1'
            - pathPrefix: '/tmp/.silverkube'
            - pathPrefix: '/tmp/.X11-unix'
            - pathPrefix: '/home/fedora'
            - pathPrefix: '/run/udev'
          hostNetwork: false
          hostIPC: false
          hostPID: false
          runAsUser:
            rule: MustRunAs
            ranges:
              - min: 1000
                max: 1000
          runAsGroup:
            rule: MustRunAs
            ranges:
              - min: 1000
                max: 1000
          supplementalGroups:
            rule: MustRunAs
            ranges:
              # User
              - min: 1000
                max: 1000
              # Video
              - min: 39
                max: 39
              # Audio
              - min: 63
                max: 63
              # Inputs
              - min: 999
                max: 999
          fsGroup:
            rule: MustRunAs
            ranges:
              - min: 1000
                max: 1000
          seLinux:
            rule: MustRunAs
            seLinuxOptions:
              user: system_u
              role: system_r
              type: silverkube.process
              level: s0

        ---
        apiVersion: policy/v1beta1
        kind: PodSecurityPolicy
        metadata:
          name: silverkube-psp
          namespace: silverkube
        spec:
          privileged: false
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          volumes:
            - 'configMap'
            - 'emptyDir'
            - 'secret'
            - 'hostPath'
          allowedHostPaths:
            - pathPrefix: '/dev/dri'
            - pathPrefix: '/dev/fb0'
            - pathPrefix: '/dev/input'
            - pathPrefix: '/dev/snd'
            - pathPrefix: '/dev/tty0'
            - pathPrefix: '/dev/tty1'
            - pathPrefix: '/tmp/.silverkube'
            - pathPrefix: '/tmp/.X11-unix'
            - pathPrefix: '/home/fedora'
            - pathPrefix: '/run/udev'
          hostNetwork: false
          hostIPC: false
          hostPID: false
          runAsUser:
            rule: MustRunAs
            ranges:
              - min: 1000
                max: 1000
          runAsGroup:
            rule: MustRunAs
            ranges:
              - min: 1000
                max: 1000
          supplementalGroups:
            rule: MustRunAs
            ranges:
              # User
              - min: 1000
                max: 1000
              # Video
              - min: 39
                max: 39
              # Audio
              - min: 63
                max: 63
              # Inputs
              - min: 999
                max: 999
          fsGroup:
            rule: MustRunAs
            ranges:
              - min: 1000
                max: 1000
          seLinux:
            rule: MustRunAs
            seLinuxOptions:
              user: system_u
              role: system_r
              type: silverkube.process
              level: s0

        ---
        apiVersion: v1
        kind: Namespace
        metadata:
          name: silverkube


        ---
        kind: ClusterRole
        apiVersion: rbac.authorization.k8s.io/v1
        kind: ClusterRole
        metadata:
          name: silverkube-psp
        rules:
          - apiGroups: ['extensions']
            resources: ['podsecuritypolicies']
            verbs:     ['use']
            resourceNames:
              - silverkube-psp

        ---
        apiVersion: rbac.authorization.k8s.io/v1
        kind: ClusterRoleBinding
        metadata:
          name: silverkube-psp-binding
        roleRef:
          kind: ClusterRole
          name: silverkube-psp
          apiGroup: rbac.authorization.k8s.io
        subjects:
        - kind: User
          name: 'system:serviceaccount:silverkube:default'
        - kind: Group
          name: system:authenticated # All authenticated users
          apiGroup: rbac.authorization.k8s.io

        ---
        kind: Role
        apiVersion: rbac.authorization.k8s.io/v1beta1
        metadata:
          namespace: silverkube
          name: silverkube-role
        rules:
        - apiGroups: [""]
          resources: ["pods", "pods/exec", "pods/log", "configmaps", "secrets"]
          verbs: ["*"]

        ---
        kind: RoleBinding
        apiVersion: rbac.authorization.k8s.io/v1beta1
        metadata:
          name: silverkube-rolebinding
          namespace: silverkube
        subjects:
        - kind: ServiceAccount
          name: default
        - kind: User
          name: 'system:serviceaccount:silverkube:default'
        roleRef:
          kind: Role
          name: silverkube-role
          apiGroup: "rbac.authorization.k8s.io"
    """)[1:])


def setup_service(name: str, args: List[Command]) -> None:
    if name == "rootlesskit" and not USERNETES:
        # No need for that service
        return
    if name.startswith("kube"):
        command_name = f"hyperkube {name}"
    else:
        command_name = name
    command_name = "/usr/libexec/silverkube/" + command_name
    if name != "rootlesskit" and USERNETES:
        # Usernetes needs to share the namespace
        command_name = str(RKJOIN) + " " + command_name
    command = command_name + " " + " ".join(args)
    unit = SYSTEMD / ("silverkube-" + name + ".service")
    unit.parent.mkdir(parents=True, exist_ok=True)
    unit.write_text(dedent(f"""
        [Unit]
        Description=Silverkube {name}

        [Service]
        Environment="PATH=/usr/libexec/silverkube/:/bin:/sbin"
        SyslogIdentifier=silverkube-{name}
        ExecStart={command}

        [Install]
        WantedBy=default.target
        """)[1:])


def generate_user_kubeconfig(ca) -> Path:
    execute(NSJOIN + ["/bin/kubectl", "apply", "-f", str(CONF / "policy.yaml")])
    print("Waiting for service account token")
    for retry in range(10):
        token = b64decode(pread(NSJOIN + [
            "/bin/kubectl", "-n", "silverkube", "get", "secrets", "-o",
            "jsonpath={.items[?(@.metadata.annotations"
            "['kubernetes\\.io/service-account\\.name']=='default')]"
            ".data.token}"
        ])[0].encode('utf-8')).decode('utf-8')
        if token:
            break
        sleep(1)
    else:
        raise RuntimeError("Couldn't get service account token")
    if USERNETES:
        kube_config_user = CONF / "kubeconfig.user"
    else:
        kube_config_user = Path("/home") / \
            environ["SUDO_USER"] / ".config" / "silverkube" / "kubeconfig"
    kube_config_user.write_text(dedent("""
        apiVersion: v1
        kind: Config
        preferences: {}
        clusters:
        - cluster:
            server: https://localhost:8043
            certificate-authority-data: %s
          name: local
        users:
        - name: silverkube
          user:
            token: %s
        contexts:
        - context:
            cluster: local
            user: silverkube
            namespace: silverkube
          name: local
        current-context: local
    """)[1:] % (ca, token))
    return kube_config_user


def generate_pvs():
    base = Path("/tmp/.silverkube")
    base.mkdir(exist_ok=True)
    base.chmod(0o700)
    chown(str(base), 1000, 1000)
    for pv in HostPaths:
        path = Path(pv.get('path', base / pv['name']))
        path.mkdir(parents=True, exist_ok=True)
        chown(str(path), 1000, 1000)
        execute(["chcon", "system_u:object_r:container_file_t:s0", str(path)])


def up() -> int:
    ca = b64(generate_certs())
    generate_kubeconfig(ca)

    for service in Services:
        name, enabled, args, files, check = service
        if not enabled:
            continue
        for fpath, fcontent in files:
            fcontent = fcontent.strip() + "\n"
            fpath.parent.mkdir(parents=True, exist_ok=True)
            if (fpath.exists() and fpath.read_text() != fcontent) \
               or not fpath.exists():
                fpath.write_text(fcontent)
                if fcontent.startswith("#!/bin"):
                    fpath.chmod(0o755)
                print(f"{fpath}: updated!")

        setup_service(name, args)

    execute(SYSTEMCTL + ["daemon-reload"])
    for service in Services:
        if not service[1]:
            continue
        name = service[0]
        print(f"Starting silverkube-{name}")
        execute(SYSTEMCTL + ["start", f"silverkube-{name}"])
    sleep(3)
    environ["KUBECONFIG"] = str(KUBECONFIG)
    for service in Services:
        name, enabled, args, files, check = service
        if not enabled:
            continue
        print(f"Checking silverkube-{name}")
        execute(SYSTEMCTL + ["is-active", f"silverkube-{name}"])
        if check:
            for retry in range(10):
                res = pread(NSJOIN + check[0].split())
                if check[1] in res[0]:
                    break
                print(".", end='')
                sleep(2)
            else:
                print(res)
                raise RuntimeError(f"Fail to check {name}")
    print("up!")
# disable psp for now
#    generate_pvs()
#    generate_policy()
#    kube_config_user = generate_user_kubeconfig(ca)
    kube_config_user = KUBECONFIG
    if USERNETES:
        kubectl = f'{RKJOIN} kubectl'
    else:
        kubectl = 'kubectl'
    print(f"alias kubectl='{kubectl} --kubeconfig {kube_config_user}'")
    return 0


def down() -> int:
    try:
        execute(SYSTEMCTL + ["kill", "silverkube-crio"])
    except RuntimeError:
        pass
    for service in reversed(Services):
        name, enabled, args, files, check = service
        if not enabled:
            continue
        print(f"Stopping silverkube-{name}")
        try:
            execute(SYSTEMCTL + ["stop", f"silverkube-{name}"])
        except RuntimeError:
            pass
    print("down!")
    try:
        if not USERNETES:
            execute(["/usr/libexec/silverkube/hyperkube",
                     "kube-proxy", "--cleanup", "--cleanup-ipvs", "--config", str(CONF / "kube-proxy.yaml")])
    except RuntimeError:
        pass
    if "silverkube" in Path("/proc/mounts").read_text():
        try:
            execute(["sudo", "sh", "-c", "umount $(grep silverkube /proc/mounts  | awk '{ print $2 }')"])
        except RuntimeError:
            pass
    execute(["rm", "-Rf", str(RUN)])
    execute(["sudo", "rm", "-Rf", str(CRIO_RUNROOT)])
    return 0


def main() -> None:
    if len(argv) == 1:
        argv.append("up")
    arg = argv[1].replace("start", "up").replace("stop", "down")
    for action in (up, down):
        if arg == action.__name__:
            exit(action())
    else:
        print("usage: silverkube up|down")


if __name__ == "__main__":
    main()

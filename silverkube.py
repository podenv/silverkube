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

from base64 import b64encode
from os import environ
from subprocess import Popen, PIPE
from time import sleep
from typing import List, Tuple
from sys import argv
from pathlib import Path
from textwrap import dedent

ca = "--cacert /var/lib/silverkube/ca.pem "
etcd_ca = (
    f"{ca} -E /var/lib/silverkube/etcd-cert.pem "
    "--key /var/lib/silverkube/etcd-key.pem")
api_ca = (
    f"{ca}  -E /var/lib/silverkube/sa-cert.pem "
    "--key /var/lib/silverkube/sa-key.pem"
)

# Types
ServiceName = str
Command = str
ExpectedOutput = str
Check = Tuple[Command, ExpectedOutput]
Service = Tuple[ServiceName, Check]
Services: List[Service] = [
    ("etcd", (f"curl {etcd_ca} https://localhost:2379/version", "etcdcluste")),
    ("kube-apiserver",
     (f"curl {api_ca} https://localhost:8043/api", "APIVersions")),
    ("kube-controller-manager", None),
    ("kube-scheduler", ("kubectl get componentstatuses", "Healthy")),
    ("crio", ("crictl --runtime-endpoint unix:///var/run/silverkube/crio.sock "
              "version", "RuntimeName:  cri-o")),
    ("kubelet", ("kubectl get nodes", "Ready")),
]
dest = Path("/var/lib/silverkube")


# Utility procedures
def execute(args: List[str]) -> None:
    if Popen(args).wait():
        raise RuntimeError(f"Fail: {args}")


def pread(args: List[str]) -> str:
    p = Popen(args, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate()
    return stdout.decode('utf-8'), stderr.decode('utf-8')


def b64(data: str) -> str:
    return b64encode(data.encode('utf-8')).decode('utf-8')

def generate_cert(name) -> None:
    key = (dest / (name + "-key.pem"))
    req = (dest / (name + "-cert.req"))
    crt = (dest / (name + "-cert.pem"))
    if not key.exists():
        execute(
            ["openssl", "genrsa", "-out", str(key), "2048"])
    if not req.exists():
        execute(
            ["openssl", "req", "-new", "-subj",
             "/C=FR/O=SoftwareFactory/CN=localhost",
             "-extensions", "v3_req", "-config", str(dest / "ca.cnf"),
             "-key", str(key), "-out", str(req)])
    if not crt.exists():
        execute(
            ["openssl", "x509", "-req", "-days", "365", "-sha256",
             "-extensions", "v3_req", "-extfile", str(dest / "ca.cnf"),
             "-CA", str(dest / "ca.pem"), "-CAkey", str(dest / "cakey.pem"),
             "-CAserial", str(dest / "ca.srl"),
             "-in", str(req), "-out", str(crt)])


def generate_certs() -> None:
    (dest / "ca.cnf").write_text(dedent("""
      [req]
      req_extensions = v3_req
      distinguished_name = req_distinguished_name

      [ req_distinguished_name ]
      commonName_default = localhost

      [ v3_req ]
      subjectAltName=@alt_names

      [alt_names]
      DNS.1 = localhost
    """))
    (dest / "ca.srl").write_text("00\n")
    if not (dest / "cakey.pem").exists():
        execute(["openssl", "req", "-nodes", "-days", "3650", "-new",
                 "-x509", "-subj", "/C=FR/O=SilverKube/OU=42",
                 "-keyout", str(dest / "cakey.pem"),
                 "-out", str(dest / "ca.pem")])
    generate_cert("etcd")
    generate_cert("sa")
    generate_cert("api")
    generate_cert("controller")
    generate_cert("crio")
    return (dest / "ca.pem").read_text()


def up() -> int:
    ca = b64(generate_certs())
    kube_config = Path("/var/lib/silverkube/kubeconfig")
    kube_config.write_text(dedent("""
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
    """)[1:] % (ca, b64((dest / "sa-key.pem").read_text()),
                b64((dest / "sa-cert.pem").read_text())))
    environ["KUBECONFIG"] = str(kube_config)
    for service, check in Services:
        print(f"Checking silverkube-{service}")
        execute(["systemctl", "start", f"silverkube-{service}"])
        execute(["systemctl", "is-active", f"silverkube-{service}"])
        if check:
            sleep(3)
            for retry in range(3):
                res = pread(check[0].split())
                if check[1] in res[0]:
                    break
                print(res)
                sleep(5)
            else:
                raise RuntimeError(f"Fail to check {service}")
    print("up!")
    print(f"export KUBECONFIG={kube_config}")
    return 0


def down() -> int:
    for service, _ in reversed(Services):
        print(f"Stopping silverkube-{service}")
        execute(["systemctl", "stop", f"silverkube-{service}"])
    print("down!")
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

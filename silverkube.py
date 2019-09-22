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

from os import environ
from subprocess import Popen, PIPE
from time import sleep
from typing import List, Tuple
from sys import argv
from pathlib import Path
from textwrap import dedent

# Types
ServiceName = str
Command = str
ExpectedOutput = str
Check = Tuple[Command, ExpectedOutput]
Service = Tuple[ServiceName, Check]
Services: List[Service] = [
    ("etcd", ("curl http://localhost:2379/version", "etcdcluster")),
    ("kube-apiserver", ("curl http://localhost:8043/api", "APIVersions")),
    ("kube-controller-manager", None),
    ("kube-scheduler", ("kubectl get componentstatuses", "Healthy")),
    ("crio", ("crictl --runtime-endpoint unix:///var/run/silverkube/crio.sock "
              "version", "RuntimeName:  cri-o")),
    ("kubelet", ("kubectl get nodes", "Ready")),
]


# Utility procedures
def execute(args: List[str]) -> None:
    if Popen(args).wait():
        raise RuntimeError(f"Fail: {args}")


def pread(args: List[str]) -> str:
    p = Popen(args, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate()
    return stdout.decode('utf-8'), stderr.decode('utf-8')


def generate_cert() -> None:
    dest = Path("/var/lib/silverkube")
    if not (dest / "key.pem").exists():
        execute(
            ["openssl", "genrsa", "-out", str(dest / "key.pem"), "2048"])
    if not (dest / "cert.pem").exists():
        execute(
            ["openssl", "req", "-new", "-x509", "-days", "365",
             "-subj", "/C=FR/O=K1S/CN=localhost",
             "-key", str(dest / "key.pem"),
             "-out", str(dest / "cert.pem")])


def up() -> int:
    generate_cert()
    kube_config = Path("/var/lib/silverkube/kubeconfig")
    kube_config.write_text(dedent("""
        apiVersion: v1
        kind: Config
        preferences: {}
        clusters:
        - cluster:
            server: http://127.0.0.1:8043
          name: local
        users:
        - name: local
        contexts:
        - context:
            cluster: local
            user: local
          name: local
        current-context: local
    """)[1:])
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

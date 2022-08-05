#!/bin/python3
# Copyright 2020 Red Hat
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
This is adapted from rootless-containers/usernetes to build
using fedora runtime without moby or containerd
"""

from os import listdir, environ
from subprocess import Popen
from typing import Tuple, List
from pathlib import Path


BASE_DIR = Path("~/.cache/silverkube").expanduser()
SRC_DIR = BASE_DIR / "src"
SOURCES_DIR = BASE_DIR / "SOURCES"
BIN_DIR = BASE_DIR / "bin"

environ["GOPATH"] = str(BASE_DIR)

USERNETES_COMMIT = "09d803c87646985ac371f1369ad03d2f9d46e896"
# Copy the pins from https://github.com/rootless-containers/usernetes/blob/master/Dockerfile
ROOTLESSKIT_COMMIT = "c5f0bd3d3d59768c1d3416ef09a6ddb6f0e1e0fb"
CRIO_COMMIT = "v1.20.9"
KUBERNETES_COMMIT = "v1.25.0-alpha.3"
SLIRP4NETNS_COMMIT = "v1.1.8"
CRUN_COMMIT = "1.4.5"
CNI_PLUGINS_COMMIT = "v1.1.1"
CONMON_RELEASE = "v2.1.0"
COREDNS_COMMIT = "v1.8.0"
KUBE_GIT_VERSION = f"{KUBERNETES_COMMIT}-usernetes"

CRICTL_VERSION = "v1.24.1"
ETCD_RELEASE = "v3.4.14"


def execute(args: List[str], cwd: Path = Path(".")) -> None:
    if Popen(args, cwd=cwd).wait():
        raise RuntimeError(f"failed: {args}")


def clone(url: str, commit: str) -> Path:
    dest = SRC_DIR / url.replace("https://", "")
    if not (dest / ".git").exists():
        dest.mkdir(parents=True, exist_ok=True)
        execute(["git", "clone", url, str(dest)])
    try:
        execute(["git", "checkout", commit], dest)
    except Exception:
        execute(["git", "fetch", "origin"], dest)
        execute(["git", "checkout", commit], dest)
    # TODO: ensure commit is correct
    return dest


def build_rootless() -> List[Path]:
    print("Building rootlesskit")
    git = clone(
        "https://github.com/rootless-containers/rootlesskit", ROOTLESSKIT_COMMIT
    )
    rkit = git / "rootlesskit"
    rctl = git / "rootlessctl"
    if not rkit.exists():
        execute(
            [
                "env",
                "CGO_ENABLED=0",
                "go",
                "build",
                "-o",
                str(rkit),
                "github.com/rootless-containers/rootlesskit/cmd/rootlesskit",
            ],
            git,
        )
    if not rctl.exists():
        execute(
            [
                "env",
                "CGO_ENABLED=0",
                "go",
                "build",
                "-o",
                str(rctl),
                "github.com/rootless-containers/rootlesskit/cmd/rootlessctl",
            ],
            git,
        )
    return [rkit, rctl]


def build_slirp() -> List[Path]:
    print("Building slirp4netns")
    git = clone(
        "https://github.com/rootless-containers/slirp4netns", SLIRP4NETNS_COMMIT
    )
    slirp = git / "slirp4netns"
    if not slirp.exists():
        execute(["./autogen.sh"], git)
        execute(["./configure"], git)
        execute(["make"], git)
    return [slirp]


def build_crun() -> List[Path]:
    print("Building crun")
    git = clone("https://github.com/containers/crun", CRUN_COMMIT)
    crun = git / "crun"
    if not crun.exists():
        execute(["./autogen.sh"], git)
        execute(["./configure"], git)
        execute(["make"], git)
    return [crun]


def build_crio() -> List[Path]:
    print("Building crio")
    git = clone("https://github.com/cri-o/cri-o", CRIO_COMMIT)
    crio = git / "bin" / "crio"
    pinns = git / "bin" / "pinns"
    crictl = BIN_DIR / "crictl"
    if not crio.exists():
        execute(["make", "bin/crio"], git)
    if not pinns.exists():
        execute(["make", "bin/pinns"], git)
    if not crictl.exists():
        execute(["curl", "-Lo", "crictl.tar.gz", f"https://github.com/kubernetes-sigs/cri-tools/releases/download/{CRICTL_VERSION}/crictl-{CRICTL_VERSION}-linux-amd64.tar.gz"], BASE_DIR)
        execute(["tar", "zxvf", "crictl.tar.gz", "-C", str(BIN_DIR)], BASE_DIR)
    return [crio, pinns, crictl]


def build_conmon() -> List[Path]:
    print("Building conmon")
    git = clone("https://github.com/containers/conmon", CONMON_RELEASE)
    conmon = git / "bin" / "conmon"
    if not conmon.exists():
        execute(["make"], git)
    return [conmon]


def build_cni() -> List[Path]:
    print("Building cni")
    git = clone("https://github.com/containernetworking/plugins", CNI_PLUGINS_COMMIT)
    if not (git / "bin" / "portmap").exists():
        execute(["./build_linux.sh"], git)
    plugins = listdir(str(git / "bin"))
    return list(map(lambda x: git / "bin" / x, sorted(plugins)))


def build_coredns() -> List[Path]:
    print("Building coredns")
    git = clone("https://github.com/coredns/coredns", COREDNS_COMMIT)
    coredns = git / "coredns"
    if not coredns.exists():
        del environ["GOPATH"]
        execute(["go", "mod", "vendor"], git)
        execute(["make"], git)
        environ["GOPATH"] = str(BASE_DIR)
    return [coredns]


def build_kube() -> List[Path]:
    print("Building kube")
    git = clone("https://github.com/kubernetes/kubernetes", KUBERNETES_COMMIT)
    cmds = ["kubelet"] + list(
        map(
            lambda n: "kube-" + n,
            ["apiserver", "controller-manager", "scheduler", "proxy"],
        )
    )

    kubes = []
    for cmd in cmds:
        kube = git / "_output" / "bin" / cmd
        if not kube.exists():
            execute(["make", "WHAT=cmd/" + cmd], git)
        kubes.append(kube)
    return kubes


def build_etcd() -> List[Path]:
    print("Building etcd")
    url = (
        "https://github.com/etcd-io/etcd/releases/download/"
        f"{ETCD_RELEASE}/etcd-{ETCD_RELEASE}-linux-amd64.tar.gz"
    )
    dest = SRC_DIR / Path(url).name
    if not dest.exists():
        execute(["curl", "-o", str(dest), "-L", url])
        # TODO: check hash
    path = SRC_DIR / f"etcd-{ETCD_RELEASE}-linux-amd64" / "etcd"
    if not path.exists():
        execute(["tar", "-C", str(SRC_DIR), "-xzf", str(dest), "--no-same-owner"])
    return [path]


BuildReq = set(
    [
        "git",
        "curl",
        "rpm-build",
        "make",
        "btrfs-progs-devel",
        "which",
        "runc",
        "autoconf",
        "automake",
        "libtool",
        "libcap-devel",
        "libslirp-devel",
        "yajl-devel",
        "glibc-static",
        "gcc",
        "gcc-c++",
        "containers-common",
        "device-mapper-devel",
        "git",
        "glib2-devel",
        "glibc-devel",
        "go",
        "gpgme-devel",
        "libassuan-devel",
        "libgpg-error-devel",
        "libseccomp-devel",
        "libselinux-devel",
        "pkgconfig",
        "bzip2",
        "selinux-policy",
        "selinux-policy-devel",
    ]
)


def main():
    SRC_DIR.mkdir(exist_ok=True, parents=True)
    BIN_DIR.mkdir(exist_ok=True, parents=True)
    SOURCES_DIR.mkdir(exist_ok=True, parents=True)
    LOCAL_INSTALL = environ.get("NO_INSTALL", "") == ""
    execute(["sudo", "dnf", "install", "-y"] + list(BuildReq))
    bins = (
        build_rootless()
        + build_slirp()
        + build_crun()
        + build_crio()
        + build_conmon()
        + build_coredns()
        + build_kube()
        + build_etcd()
    )
    cnis = build_cni()

    specfile = [
        "Name: silverkube",
        "Version: 0.3.0",
        "Release: 1%{?dist}",
        "Summary: A kubernetes service for desktop",
        "",
        "Requires: iptables, ipset, conntrack-tools, containers-common, kubernetes-client, openssl",
        "Requires(post): udica",
        "Requires(post): coreutils",
        "",
        "License: ASL",
        "URL: https://github.com/podenv/silverkube",
        "",
        "Source1: silverkube.py",
        "Source2: silverkube.cil",
    ]
    for idx, source in zip(range(100, 1000), bins + cnis):
        src_name = str(source).split(".cache/silverkube/")[1]
        specfile.append(f"Source{idx}: {src_name}")

    specfile.extend(
        [
            "",
            "%description",
            "A kubernetes service for desktop",
            "",
            "%prep",
            "",
            "%build",
            "",
            "%install",
            "install -p -D -m 0755 %{SOURCE1} %{buildroot}/bin/silverkube",
            "install -p -D -m 0644 %{SOURCE2} "
            "%{buildroot}/usr/share/silverkube/silverkube.cil",
            "",
        ]
    )

    if LOCAL_INSTALL:
        def ln(p, d):
            execute(["sudo", "ln", "-sf", str(p), str(d / p.name)])

        execute(["sudo", "mkdir", "-p", "/usr/libexec/silverkube/cni"])
        for p in bins:
            ln(p, Path("/usr/libexec/silverkube"))
        for p in cnis:
            ln(p, Path("/usr/libexec/silverkube/cni"))

    def sd(mode: str, path: str, srcs: List[Path]) -> List[Tuple[str, str]]:
        return list(map(lambda x: (mode, path + "/" + x.name), srcs))

    for idx, (mode, dest) in zip(
        range(100, 1000),
        sd("755", "usr/libexec/silverkube", bins)
        + sd("755", "usr/libexec/silverkube/cni", cnis),
    ):
        specfile.append(
            "install -p -D -m 0%s %%{SOURCE%d} %%{buildroot}/%s" % (mode, idx, dest)
        )

    specfile.extend(
        [
            "",
            "%post",
            "chcon -v system_u:object_r:container_runtime_exec_t:s0 "
            "/usr/libexec/silverkube/crio",
            "semodule -i /usr/share/silverkube/silverkube.cil "
            "/usr/share/udica/templates/*.cil",
            "",
            "%files",
            "/bin/silverkube",
            "/usr/libexec/silverkube",
            "/usr/share/silverkube",
            "",
            "%changelog",
            "* Mon Dec 14 2020 Tristan Cacqueray <tdecacqu@redhat.com>",
            "- Initial packaging",
            ""
        ]
    )
    Path("silverkube.spec").write_text("\n".join(specfile))

    for local in bins + cnis + [Path("silverkube.py"), Path("silverkube.cil")]:
        dest = SOURCES_DIR / local.name
        if not dest.exists():
            execute(["ln", "-sf", local.resolve(), str(dest)])

    execute(
        [
            "rpmbuild",
            "--define",
            "_sourcedir %s" % SOURCES_DIR.resolve(),
            "--define",
            "_topdir %s" % Path("rpmbuild").resolve(),
            "-ba",
            "silverkube.spec",
        ]
    )


if __name__ == "__main__":
    main()

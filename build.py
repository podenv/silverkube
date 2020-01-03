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
This is adapted from rootless-containers/usernetes to build
using fedora runtime without moby or containerd
"""

from os import listdir, environ
from subprocess import Popen
from typing import Tuple, List
from pathlib import Path
from glob import glob


BASE_DIR = Path("~/.cache/silverkube").expanduser()
SRC_DIR = BASE_DIR / "src"
SOURCES_DIR = BASE_DIR / "SOURCES"
BIN_DIR = BASE_DIR / "bin"

environ["GOPATH"] = str(BASE_DIR)

# TODO: build coredns

# 2019-09-02T05:32:23Z
ROOTLESSKIT_COMMIT = "182be5f88e62f3568b86331356d237910909b24e"
# 2019-08-30T11:19:53Z
SLIRP4NETNS_COMMIT = "f9503feb2adcd33ad817f954d294f2076de80f45"
# 2019-09-18T18:53:36Z
RUNC_COMMIT = "2186cfa3cd52b8e00b1de76db7859cacdf7b1f94"
# 2019-09-20T19:14:38Z
CRIO_COMMIT = "d9c19635885197f8667c9f7e9b9e7c6764b19921"
# 2019-09-18T15:12:43Z
CNI_PLUGINS_COMMIT = "497560f35f2cef2695f1690137b0bba98adf849b"
# 2019-09-24T20:37:53Z
KUBERNETES_COMMIT = "948870b5840add1ba4068e3d27d54ea353839992"
CONMON_RELEASE = "v2.0.1"
# Kube's build script requires KUBE_GIT_VERSION to be set to a semver string
KUBE_GIT_VERSION = "v1.17.0-usernetes"
# 01/23/2017 (v.1.7.3.2)
SOCAT_COMMIT = "cef0e039a89fe3b38e36090d9fe4be000973e0be"
FLANNEL_RELEASE = "v0.11.0"
GOTASK_RELEASE = "v2.7.0"
ETCD_RELEASE = "v3.4.1"
BAZEL_RELEASE = "0.29.1"


def execute(args: List[str], cwd: Path = Path(".")) -> None:
    if Popen(args, cwd=cwd).wait():
        raise RuntimeError(f"failed: {args}")


def clone(url: str, commit: str) -> Path:
    dest = SRC_DIR / url.replace("https://", "")
    if not (dest / ".git").exists():
        dest.mkdir(parents=True, exist_ok=True)
        execute(["git", "clone", url, str(dest)])
    try:
        execute(["git", "checkout", commit],
                dest)
    except Exception:
        # TODO: ensure commit is correct
        raise
    return dest


def build_rootless() -> List[Path]:
    print("Building rootlesskit")
    git = clone("https://github.com/rootless-containers/rootlesskit",
                ROOTLESSKIT_COMMIT)
    rkit = git / "rootlesskit"
    rctl = git / "rootlessctl"
    if not rkit.exists():
        execute(["env", "CGO_ENABLED=0", "go", "build", "-o", str(rkit),
                 "github.com/rootless-containers/rootlesskit/cmd/rootlesskit"],
                git)
    if not rctl.exists():
        execute(["env", "CGO_ENABLED=0", "go", "build", "-o", str(rctl),
                 "github.com/rootless-containers/rootlesskit/cmd/rootlessctl"],
                git)
    return [rkit, rctl]


def build_slirp() -> List[Path]:
    print("Building slirp4netns")
    git = clone("https://github.com/rootless-containers/slirp4netns",
                SLIRP4NETNS_COMMIT)
    slirp = git / "slirp4netns"
    if not slirp.exists():
        execute(["./autogen.sh"], git)
        execute(["./configure"], git)
        execute(["make"], git)
    return [slirp]


def build_runc() -> List[Path]:
    print("Building runc")
    git = clone("https://github.com/opencontainers/runc",
                RUNC_COMMIT)
    runc = git / "runc"
    if not runc.exists():
        execute(["make", "BUILDTAGS=seccomp selinux"], git)
    return [runc]


def build_crio() -> List[Path]:
    print("Building crio")
    git = clone("https://github.com/cri-o/cri-o", CRIO_COMMIT)
    crio = git / "bin" / "crio"
    crictl = BIN_DIR / "crictl"
    if not crio.exists():
        execute(["make", "bin/crio"], git)
    if not crictl.exists():
        execute(["go", "get",
                 "github.com/kubernetes-sigs/cri-tools/cmd/crictl"])
    return [crio, crictl]


def build_conmon() -> List[Path]:
    print("Building conmon")
    git = clone("https://github.com/containers/conmon",
                CONMON_RELEASE)
    conmon = git / "bin" / "conmon"
    if not conmon.exists():
        execute(["make"], git)
    return [conmon]


def build_cni() -> List[Path]:
    print("Building cni")
    git = clone("https://github.com/containernetworking/plugins",
                CNI_PLUGINS_COMMIT)
    if not (git / "bin" / "portmap").exists():
        execute(["./build_linux.sh"], git)
    plugins = listdir(str(git / "bin"))
    return list(map(lambda x: git / "bin" / x, sorted(plugins)))


def build_kube() -> List[Path]:
    print("Building kube")
    bazel = Path("/usr/local/bin/bazel")
    if not bazel.exists():
        execute(["sudo", "curl", "-Lo", "/usr/local/bin/bazel",
                 f"https://github.com/bazelbuild/bazel/releases/download/"
                 f"{BAZEL_RELEASE}/bazel-{BAZEL_RELEASE}-linux-x86_64"])
        execute(["sudo", "chmod", "+x", str(bazel)])
    git = clone("https://github.com/kubernetes/kubernetes",
                KUBERNETES_COMMIT)
    kube = git / "bazel-bin" / "cmd" / "hyperkube" / "hyperkube"
    if not kube.exists():
        execute(["git", "config", "user.email", "nobody@example.com"], git)
        execute(["git", "config", "user.name", "Silverkube Build Script"], git)
        patches = clone("https://github.com/rootless-containers/usernetes",
                        "d58792bd5d4c56c4dda844ea119ee05a6b0d1808") / \
            "src" / "patches" / "kubernetes"
        execute(["git", "am"] + glob(str(patches) + "/*"), git)
        execute(["git", "show", "--summary"], git)
        execute(["env", "KUBE_GIT_VERSION=" + KUBE_GIT_VERSION,
                 "bazel", "build", "cmd/hyperkube"], git)
    return [kube]


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
        execute(["tar", "-C", str(SRC_DIR), "-xzf", str(dest),
                 "--no-same-owner"])
    return [path]


BuildReq = set([
    "git", "curl", "rpm-build", "make", "btrfs-progs-devel", "which", "runc",
    "autoconf", "automake", "libtool", "libcap-devel", "glibc-static",
    "gcc", "gcc-c++",
    "containers-common", "device-mapper-devel", "git", "glib2-devel",
    "glibc-devel", "go", "gpgme-devel", "libassuan-devel",
    "libgpg-error-devel", "libseccomp-devel", "libselinux-devel", "pkgconfig",
    "bzip2", "selinux-policy", "selinux-policy-devel"])


def main():
    SRC_DIR.mkdir(exist_ok=True, parents=True)
    SOURCES_DIR.mkdir(exist_ok=True, parents=True)
    execute(["sudo", "dnf", "install", "-y"] + list(BuildReq))
    bins = (
        build_rootless() +
        build_slirp() +
        build_runc() +
        build_crio() +
        build_conmon() +
        build_kube() +
        build_etcd()
    )
    cnis = build_cni()

    specfile = [
        "Name: silverkube",
        "Version: 0.0.2",
        "Release: 1%{?dist}",
        "Summary: A kubernetes service for desktop",
        "",
        "Requires: iptables, ipset, conntrack-tools"
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
        src_name = str(source).replace('/root/.cache/silverkube/', '')
        specfile.append(f"Source{idx}: {src_name}")

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
        "install -p -D -m 0755 %{SOURCE1} %{buildroot}/bin/silverkube",
        "install -p -D -m 0644 %{SOURCE2} "
        "%{buildroot}/usr/share/silverkube/silverkube.cil",
        "",
    ])

    def sd(mode: str, path: str, srcs: List[Path]) -> List[Tuple[str, str]]:
        return list(map(lambda x: (mode, path + "/" + x.name), srcs))

    for idx, (mode, dest) in zip(
            range(100, 1000),
            sd("755", "usr/libexec/silverkube", bins) +
            sd("755", "usr/libexec/silverkube/cni", cnis)):
        specfile.append(
            "install -p -D -m 0%s %%{SOURCE%d} %%{buildroot}/%s" % (
                mode, idx, dest))

    specfile.extend([
        "", "%post",
        "chcon -v system_u:object_r:container_runtime_exec_t:s0 "
        "/usr/libexec/silverkube/runc /usr/libexec/silverkube/crio",
        "semodule -i /usr/share/silverkube/silverkube.cil "
        "/usr/share/udica/templates/*.cil",
        "", "%files",
        "/bin/silverkube",
        "/usr/libexec/silverkube",
        "/usr/share/silverkube",
        "", "%changelog",
        "* Sat Sep 21 2019 Tristan Cacqueray <tdecacqu@redhat.com>",
        "- Initial packaging"
    ])
    Path("silverkube.spec").write_text("\n".join(specfile))

    for local in bins + cnis + [Path("silverkube.py"), Path("silverkube.cil")]:
        dest = SOURCES_DIR / local.name
        if not dest.exists():
            execute(["ln", "-sf", local.resolve(), str(dest)])

    execute(["rpmbuild", "--define", "_sourcedir %s" % SOURCES_DIR.resolve(),
             "--define", "_topdir %s" % Path('rpmbuild').resolve(),
             "-ba", "silverkube.spec"])


if __name__ == "__main__":
    main()

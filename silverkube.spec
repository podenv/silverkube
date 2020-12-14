Name: silverkube
Version: 0.1.0
Release: 1%{?dist}
Summary: A kubernetes service for desktop

Requires: iptables, ipset, conntrack-tools, containers-common, kubernetes-client
Requires(post): udica
Requires(post): coreutils

License: ASL
URL: https://github.com/podenv/silverkube

Source1: silverkube.py
Source2: silverkube.cil
Source100: src/github.com/rootless-containers/rootlesskit/rootlesskit
Source101: src/github.com/rootless-containers/rootlesskit/rootlessctl
Source102: src/github.com/rootless-containers/slirp4netns/slirp4netns
Source103: src/github.com/containers/crun/crun
Source104: src/github.com/cri-o/cri-o/bin/crio
Source105: src/github.com/cri-o/cri-o/bin/pinns
Source106: bin/crictl
Source107: src/github.com/containers/conmon/bin/conmon
Source108: src/github.com/coredns/coredns/coredns
Source109: src/github.com/kubernetes/kubernetes/bazel-out/k8-fastbuild/bin/cmd/kubelet/kubelet_/kubelet
Source110: src/github.com/kubernetes/kubernetes/bazel-out/k8-fastbuild-ST-4c64f0b3d5c7/bin/cmd/kube-apiserver/kube-apiserver_/kube-apiserver
Source111: src/github.com/kubernetes/kubernetes/bazel-out/k8-fastbuild-ST-4c64f0b3d5c7/bin/cmd/kube-controller-manager/kube-controller-manager_/kube-controller-manager
Source112: src/github.com/kubernetes/kubernetes/bazel-out/k8-fastbuild-ST-4c64f0b3d5c7/bin/cmd/kube-scheduler/kube-scheduler_/kube-scheduler
Source113: src/github.com/kubernetes/kubernetes/bazel-out/k8-fastbuild-ST-4c64f0b3d5c7/bin/cmd/kube-proxy/kube-proxy_/kube-proxy
Source114: src/etcd-v3.4.14-linux-amd64/etcd
Source115: src/github.com/containernetworking/plugins/bin/bandwidth
Source116: src/github.com/containernetworking/plugins/bin/bridge
Source117: src/github.com/containernetworking/plugins/bin/dhcp
Source118: src/github.com/containernetworking/plugins/bin/firewall
Source119: src/github.com/containernetworking/plugins/bin/flannel
Source120: src/github.com/containernetworking/plugins/bin/host-device
Source121: src/github.com/containernetworking/plugins/bin/host-local
Source122: src/github.com/containernetworking/plugins/bin/ipvlan
Source123: src/github.com/containernetworking/plugins/bin/loopback
Source124: src/github.com/containernetworking/plugins/bin/macvlan
Source125: src/github.com/containernetworking/plugins/bin/portmap
Source126: src/github.com/containernetworking/plugins/bin/ptp
Source127: src/github.com/containernetworking/plugins/bin/sbr
Source128: src/github.com/containernetworking/plugins/bin/static
Source129: src/github.com/containernetworking/plugins/bin/tuning
Source130: src/github.com/containernetworking/plugins/bin/vlan

%description
A kubernetes service for desktop

%prep

%build

%install
install -p -D -m 0755 %{SOURCE1} %{buildroot}/bin/silverkube
install -p -D -m 0644 %{SOURCE2} %{buildroot}/usr/share/silverkube/silverkube.cil

install -p -D -m 0755 %{SOURCE100} %{buildroot}/usr/libexec/silverkube/rootlesskit
install -p -D -m 0755 %{SOURCE101} %{buildroot}/usr/libexec/silverkube/rootlessctl
install -p -D -m 0755 %{SOURCE102} %{buildroot}/usr/libexec/silverkube/slirp4netns
install -p -D -m 0755 %{SOURCE103} %{buildroot}/usr/libexec/silverkube/crun
install -p -D -m 0755 %{SOURCE104} %{buildroot}/usr/libexec/silverkube/crio
install -p -D -m 0755 %{SOURCE105} %{buildroot}/usr/libexec/silverkube/pinns
install -p -D -m 0755 %{SOURCE106} %{buildroot}/usr/libexec/silverkube/crictl
install -p -D -m 0755 %{SOURCE107} %{buildroot}/usr/libexec/silverkube/conmon
install -p -D -m 0755 %{SOURCE108} %{buildroot}/usr/libexec/silverkube/coredns
install -p -D -m 0755 %{SOURCE109} %{buildroot}/usr/libexec/silverkube/kubelet
install -p -D -m 0755 %{SOURCE110} %{buildroot}/usr/libexec/silverkube/kube-apiserver
install -p -D -m 0755 %{SOURCE111} %{buildroot}/usr/libexec/silverkube/kube-controller-manager
install -p -D -m 0755 %{SOURCE112} %{buildroot}/usr/libexec/silverkube/kube-scheduler
install -p -D -m 0755 %{SOURCE113} %{buildroot}/usr/libexec/silverkube/kube-proxy
install -p -D -m 0755 %{SOURCE114} %{buildroot}/usr/libexec/silverkube/etcd
install -p -D -m 0755 %{SOURCE115} %{buildroot}/usr/libexec/silverkube/cni/bandwidth
install -p -D -m 0755 %{SOURCE116} %{buildroot}/usr/libexec/silverkube/cni/bridge
install -p -D -m 0755 %{SOURCE117} %{buildroot}/usr/libexec/silverkube/cni/dhcp
install -p -D -m 0755 %{SOURCE118} %{buildroot}/usr/libexec/silverkube/cni/firewall
install -p -D -m 0755 %{SOURCE119} %{buildroot}/usr/libexec/silverkube/cni/flannel
install -p -D -m 0755 %{SOURCE120} %{buildroot}/usr/libexec/silverkube/cni/host-device
install -p -D -m 0755 %{SOURCE121} %{buildroot}/usr/libexec/silverkube/cni/host-local
install -p -D -m 0755 %{SOURCE122} %{buildroot}/usr/libexec/silverkube/cni/ipvlan
install -p -D -m 0755 %{SOURCE123} %{buildroot}/usr/libexec/silverkube/cni/loopback
install -p -D -m 0755 %{SOURCE124} %{buildroot}/usr/libexec/silverkube/cni/macvlan
install -p -D -m 0755 %{SOURCE125} %{buildroot}/usr/libexec/silverkube/cni/portmap
install -p -D -m 0755 %{SOURCE126} %{buildroot}/usr/libexec/silverkube/cni/ptp
install -p -D -m 0755 %{SOURCE127} %{buildroot}/usr/libexec/silverkube/cni/sbr
install -p -D -m 0755 %{SOURCE128} %{buildroot}/usr/libexec/silverkube/cni/static
install -p -D -m 0755 %{SOURCE129} %{buildroot}/usr/libexec/silverkube/cni/tuning
install -p -D -m 0755 %{SOURCE130} %{buildroot}/usr/libexec/silverkube/cni/vlan

%post
chcon -v system_u:object_r:container_runtime_exec_t:s0 /usr/libexec/silverkube/runc /usr/libexec/silverkube/crio
semodule -i /usr/share/silverkube/silverkube.cil /usr/share/udica/templates/*.cil

%files
/bin/silverkube
/usr/libexec/silverkube
/usr/share/silverkube

%changelog
* Mon Dec 14 2020 Tristan Cacqueray <tdecacqu@redhat.com>
- Initial packaging
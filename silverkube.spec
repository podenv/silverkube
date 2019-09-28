Name: silverkube
Version: 0.0.2
Release: 1%{?dist}
Summary: A kubernetes service for desktop

Requires(post): udica
Requires(post): coreutils

License: ASL
URL: https://github.com/podenv/silverkube

Source1: silverkube.py
Source2: silverkube.cil
Source100: src/github.com/rootless-containers/rootlesskit/rootlesskit
Source101: src/github.com/rootless-containers/rootlesskit/rootlessctl
Source102: src/github.com/rootless-containers/slirp4netns/slirp4netns
Source103: src/github.com/opencontainers/runc/runc
Source104: src/github.com/cri-o/cri-o/bin/crio
Source105: bin/crictl
Source106: src/github.com/containers/conmon/bin/conmon
Source107: src/github.com/kubernetes/kubernetes/bazel-bin/cmd/hyperkube/hyperkube
Source108: src/etcd-v3.4.1-linux-amd64/etcd
Source109: src/github.com/containernetworking/plugins/bin/bandwidth
Source110: src/github.com/containernetworking/plugins/bin/bridge
Source111: src/github.com/containernetworking/plugins/bin/dhcp
Source112: src/github.com/containernetworking/plugins/bin/firewall
Source113: src/github.com/containernetworking/plugins/bin/flannel
Source114: src/github.com/containernetworking/plugins/bin/host-device
Source115: src/github.com/containernetworking/plugins/bin/host-local
Source116: src/github.com/containernetworking/plugins/bin/ipvlan
Source117: src/github.com/containernetworking/plugins/bin/loopback
Source118: src/github.com/containernetworking/plugins/bin/macvlan
Source119: src/github.com/containernetworking/plugins/bin/portmap
Source120: src/github.com/containernetworking/plugins/bin/ptp
Source121: src/github.com/containernetworking/plugins/bin/sbr
Source122: src/github.com/containernetworking/plugins/bin/static
Source123: src/github.com/containernetworking/plugins/bin/tuning
Source124: src/github.com/containernetworking/plugins/bin/vlan

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
install -p -D -m 0755 %{SOURCE103} %{buildroot}/usr/libexec/silverkube/runc
install -p -D -m 0755 %{SOURCE104} %{buildroot}/usr/libexec/silverkube/crio
install -p -D -m 0755 %{SOURCE105} %{buildroot}/usr/libexec/silverkube/crictl
install -p -D -m 0755 %{SOURCE106} %{buildroot}/usr/libexec/silverkube/conmon
install -p -D -m 0755 %{SOURCE107} %{buildroot}/usr/libexec/silverkube/hyperkube
install -p -D -m 0755 %{SOURCE108} %{buildroot}/usr/libexec/silverkube/etcd
install -p -D -m 0755 %{SOURCE109} %{buildroot}/usr/libexec/silverkube/cni/bandwidth
install -p -D -m 0755 %{SOURCE110} %{buildroot}/usr/libexec/silverkube/cni/bridge
install -p -D -m 0755 %{SOURCE111} %{buildroot}/usr/libexec/silverkube/cni/dhcp
install -p -D -m 0755 %{SOURCE112} %{buildroot}/usr/libexec/silverkube/cni/firewall
install -p -D -m 0755 %{SOURCE113} %{buildroot}/usr/libexec/silverkube/cni/flannel
install -p -D -m 0755 %{SOURCE114} %{buildroot}/usr/libexec/silverkube/cni/host-device
install -p -D -m 0755 %{SOURCE115} %{buildroot}/usr/libexec/silverkube/cni/host-local
install -p -D -m 0755 %{SOURCE116} %{buildroot}/usr/libexec/silverkube/cni/ipvlan
install -p -D -m 0755 %{SOURCE117} %{buildroot}/usr/libexec/silverkube/cni/loopback
install -p -D -m 0755 %{SOURCE118} %{buildroot}/usr/libexec/silverkube/cni/macvlan
install -p -D -m 0755 %{SOURCE119} %{buildroot}/usr/libexec/silverkube/cni/portmap
install -p -D -m 0755 %{SOURCE120} %{buildroot}/usr/libexec/silverkube/cni/ptp
install -p -D -m 0755 %{SOURCE121} %{buildroot}/usr/libexec/silverkube/cni/sbr
install -p -D -m 0755 %{SOURCE122} %{buildroot}/usr/libexec/silverkube/cni/static
install -p -D -m 0755 %{SOURCE123} %{buildroot}/usr/libexec/silverkube/cni/tuning
install -p -D -m 0755 %{SOURCE124} %{buildroot}/usr/libexec/silverkube/cni/vlan

%post
chcon -v system_u:object_r:container_runtime_exec_t:s0 /usr/libexec/silverkube/runc /usr/libexec/silverkube/crio
semodule -i /usr/share/silverkube/silverkube.cil /usr/share/udica/templates/{base_container.cil,net_container.cil,x_container.cil}

%files
/bin/silverkube
/usr/libexec/silverkube
/usr/share/silverkube

%changelog
* Sat Sep 21 2019 Tristan Cacqueray <tdecacqu@redhat.com>
- Initial packaging
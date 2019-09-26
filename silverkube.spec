Name: silverkube
Version: 0.0.2
Release: 1%{?dist}
Summary: A kubernetes service for desktop

License: ASL
URL: https://github.com/podenv/silverkube

Source1: silverkube.py
Source100: rootlesskit
Source101: rootlessctl
Source102: slirp4netns
Source103: runc
Source104: crio
Source105: crictl
Source106: conmon
Source107: hyperkube
Source108: etcd
Source109: bandwidth
Source110: bridge
Source111: dhcp
Source112: firewall
Source113: flannel
Source114: host-device
Source115: host-local
Source116: ipvlan
Source117: loopback
Source118: macvlan
Source119: portmap
Source120: ptp
Source121: sbr
Source122: static
Source123: tuning
Source124: vlan

%description
A kubernetes service for desktop

%prep

%build

%install
install -p -D -m 0755 %{SOURCE1} %{buildroot}/bin/silverkube

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

%files
/bin/silverkube
/usr/libexec/silverkube

%changelog
* Sat Sep 21 2019 Tristan Cacqueray <tdecacqu@redhat.com>
- Initial packaging
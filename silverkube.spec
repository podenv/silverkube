Name: silverkube
Version: 0.0.1
Release: 1%{?dist}
Summary: A kubernetes service for desktop

License: ASL
URL: https://github.com/podenv/silverkube

Requires: runc, cri-tools, kubernetes-client, buildah

Source1: silverkube.py
Source100: crio.conf
Source101: kubelet-config.yaml
Source102: bridge.conflist
Source103: kubelet-cgroups.conf
Source104: silverkube-etcd.service
Source105: silverkube-kube-apiserver.service
Source106: silverkube-kube-controller-manager.service
Source107: silverkube-kube-scheduler.service
Source108: silverkube-kubelet.service
Source109: silverkube-crio.service
Source110: kube-apiserver
Source111: kube-controller-manager
Source112: kube-scheduler
Source113: kubelet
Source114: etcd
Source115: crio
Source116: conmon
Source117: bandwidth
Source118: bridge
Source119: dhcp
Source120: firewall
Source121: flannel
Source122: host-device
Source123: host-local
Source124: ipvlan
Source125: loopback
Source126: macvlan
Source127: portmap
Source128: ptp
Source129: sbr
Source130: static
Source131: tuning
Source132: vlan

%description
A kubernetes service for desktop

%prep

%build

%install
install -p -d -m 0700 %{buildroot}/etc/silverkube
install -p -d -m 0700 %{buildroot}/var/run/silverkube
install -p -d -m 0700 %{buildroot}/var/lib/silverkube
install -p -d -m 0700 %{buildroot}/var/log/silverkube
install -p -D -m 0755 %{SOURCE1} %{buildroot}/bin/silverkube

install -p -D -m 0644 %{SOURCE100} %{buildroot}/etc/silverkube/crio.conf
install -p -D -m 0644 %{SOURCE101} %{buildroot}/etc/silverkube/kubelet-config.yaml
install -p -D -m 0644 %{SOURCE102} %{buildroot}/etc/silverkube/net.d/bridge.conflist
install -p -D -m 0644 %{SOURCE103} %{buildroot}/etc/systemd/system.conf.d/kubelet-cgroups.conf
install -p -D -m 0644 %{SOURCE104} %{buildroot}/%{_unitdir}/silverkube-etcd.service
install -p -D -m 0644 %{SOURCE105} %{buildroot}/%{_unitdir}/silverkube-kube-apiserver.service
install -p -D -m 0644 %{SOURCE106} %{buildroot}/%{_unitdir}/silverkube-kube-controller-manager.service
install -p -D -m 0644 %{SOURCE107} %{buildroot}/%{_unitdir}/silverkube-kube-scheduler.service
install -p -D -m 0644 %{SOURCE108} %{buildroot}/%{_unitdir}/silverkube-kubelet.service
install -p -D -m 0644 %{SOURCE109} %{buildroot}/%{_unitdir}/silverkube-crio.service
install -p -D -m 0755 %{SOURCE110} %{buildroot}/usr/libexec/silverkube/kube-apiserver
install -p -D -m 0755 %{SOURCE111} %{buildroot}/usr/libexec/silverkube/kube-controller-manager
install -p -D -m 0755 %{SOURCE112} %{buildroot}/usr/libexec/silverkube/kube-scheduler
install -p -D -m 0755 %{SOURCE113} %{buildroot}/usr/libexec/silverkube/kubelet
install -p -D -m 0755 %{SOURCE114} %{buildroot}/usr/libexec/silverkube/etcd
install -p -D -m 0755 %{SOURCE115} %{buildroot}/usr/libexec/silverkube/crio
install -p -D -m 0755 %{SOURCE116} %{buildroot}/usr/libexec/silverkube/conmon
install -p -D -m 0755 %{SOURCE117} %{buildroot}/usr/libexec/silverkube/cni/bandwidth
install -p -D -m 0755 %{SOURCE118} %{buildroot}/usr/libexec/silverkube/cni/bridge
install -p -D -m 0755 %{SOURCE119} %{buildroot}/usr/libexec/silverkube/cni/dhcp
install -p -D -m 0755 %{SOURCE120} %{buildroot}/usr/libexec/silverkube/cni/firewall
install -p -D -m 0755 %{SOURCE121} %{buildroot}/usr/libexec/silverkube/cni/flannel
install -p -D -m 0755 %{SOURCE122} %{buildroot}/usr/libexec/silverkube/cni/host-device
install -p -D -m 0755 %{SOURCE123} %{buildroot}/usr/libexec/silverkube/cni/host-local
install -p -D -m 0755 %{SOURCE124} %{buildroot}/usr/libexec/silverkube/cni/ipvlan
install -p -D -m 0755 %{SOURCE125} %{buildroot}/usr/libexec/silverkube/cni/loopback
install -p -D -m 0755 %{SOURCE126} %{buildroot}/usr/libexec/silverkube/cni/macvlan
install -p -D -m 0755 %{SOURCE127} %{buildroot}/usr/libexec/silverkube/cni/portmap
install -p -D -m 0755 %{SOURCE128} %{buildroot}/usr/libexec/silverkube/cni/ptp
install -p -D -m 0755 %{SOURCE129} %{buildroot}/usr/libexec/silverkube/cni/sbr
install -p -D -m 0755 %{SOURCE130} %{buildroot}/usr/libexec/silverkube/cni/static
install -p -D -m 0755 %{SOURCE131} %{buildroot}/usr/libexec/silverkube/cni/tuning
install -p -D -m 0755 %{SOURCE132} %{buildroot}/usr/libexec/silverkube/cni/vlan

%post
%systemd_post silverkube-etcd.service
%systemd_post silverkube-kube-apiserver.service
%systemd_post silverkube-kube-controller-manager.service
%systemd_post silverkube-kube-scheduler.service
%systemd_post silverkube-kubelet.service
%systemd_post silverkube-crio.service

%preun
%systemd_preun silverkube-etcd.service
%systemd_preun silverkube-kube-apiserver.service
%systemd_preun silverkube-kube-controller-manager.service
%systemd_preun silverkube-kube-scheduler.service
%systemd_preun silverkube-kubelet.service
%systemd_preun silverkube-crio.service

%postun
%systemd_postun silverkube-etcd.service
%systemd_postun silverkube-kube-apiserver.service
%systemd_postun silverkube-kube-controller-manager.service
%systemd_postun silverkube-kube-scheduler.service
%systemd_postun silverkube-kubelet.service
%systemd_postun silverkube-crio.service

%files
%config(noreplace) /etc/systemd/system.conf.d/kubelet-cgroups.conf
%config(noreplace) /etc/silverkube/crio.conf
%config(noreplace) /etc/silverkube/kubelet-config.yaml
%config(noreplace) /etc/silverkube/net.d/bridge.conflist
%dir /etc/silverkube
%dir /var/lib/silverkube
%dir /var/run/silverkube
%dir /var/log/silverkube
/bin/silverkube
/usr/libexec/silverkube
%{_unitdir}/silverkube-*

%changelog
* Sat Sep 21 2019 Tristan Cacqueray <tdecacqu@redhat.com>
- Initial packaging
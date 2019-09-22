Silverkube - a kubernetes service for desktop
=============================================

The goal is to provide a kubernetes service suitable to manage
a desktop workstation:

* Minimal services to be started early
* Basic auth enough to let a container starts more container

This process is pretty much an experimental work in progress,
use at your own risk.

Setup
-----

On a fedora-30 server virtual machine:

* Prepare the host

```shell
dnf install -y buildah podman
# umount tmp if instance has less than 1GB for buildah
umount /tmp
```

* Build and install the service

```shell
mkdir -p ~/.cache/silverkube-sources
podman run --rm -it \
  -v $HOME/.cache/silverkube-sources:/root/.cache/silverkube-sources:Z \
  -v $(pwd):/data:Z --workdir /data \
  registry.fedoraproject.org/fedora:30 python3 build.py
dnf install -y rpmbuild/RPMS/x86_64/silverkube*.rpm
```

* Build the silverkube image

```shell
buildah bud -f Containerfile -t silverkube .
```

Usage
-----

* Start the services

```shell
# mount /tmp
# silverkube start
Checking silverkube-etcd
active
Checking silverkube-kube-apiserver
active
Checking silverkube-kube-controller-manager
active
Checking silverkube-kube-scheduler
active
Checking silverkube-crio
active
Checking silverkube-kubelet
active
up!
export KUBECONFIG=/var/lib/silverkube/kubeconfig
```

* Start the desktop

```shell
$ kubectl apply -f desktop.yaml
persistentvolume/pulse-socket created
persistentvolume/xorg-socket created
persistentvolumeclaim/pulse-socket created
persistentvolumeclaim/xorg-socket created
pod/display-server created
pod/window-manager created
$ kubectl get pods
NAME             READY   STATUS    RESTARTS   AGE
display-server   1/1     Running   0          81s
window-manager   1/1     Running   0          24s
$ kubectl exec -it window-manager ps afx
  PID TTY      STAT   TIME COMMAND
   26 pts/2    Rs+    0:00 ps afx
    1 pts/0    Ss+    0:00 /bin/xmonad
    8 ?        Ss     0:00 xterm
   10 pts/1    Ss+    0:00  \_ bash
```

* Stop everything:

```shell
$ kubectl delete -f desktop.yaml
persistentvolume "pulse-socket" deleted
persistentvolume "xorg-socket" deleted
persistentvolumeclaim "pulse-socket" deleted
persistentvolumeclaim "xorg-socket" deleted
pod "display-server" deleted
pod "window-manager" deleted
$ sudo silverkube stop
Stopping silverkube-kubelet
Stopping silverkube-crio
Stopping silverkube-kube-scheduler
Stopping silverkube-kube-controller-manager
Stopping silverkube-kube-apiserver
Stopping silverkube-etcd
down!
```

Roadmap
-------

* create restricted service account
* implement a tool to start applications from the desktop environment
* add security context to prevent privileged pod

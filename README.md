Silverkube - a kubernetes service for desktop
=============================================

The goal is to provide a kubernetes service suitable to manage
a desktop workstation:

* Minimal services to be started early.
* Basic auth enough to let a container starts more containers.

This process is pretty much an experimental work in progress,
use at your own risk.

Setup
-----

On a fedora-30 server virtual machine:

* Prepare the host

```shell
$ sudo dnf install -y buildah podman
# umount tmp if instance has less than 1GB for buildah
$ sudo umount /tmp
```

* Build and install the service

```shell
$ mkdir -p ~/.cache/silverkube-sources
$ podman run --rm -it \
  -v $HOME/.cache/silverkube-sources:/root/.cache/silverkube-sources:Z \
  -v $(pwd):/data:Z --workdir /data \
  registry.fedoraproject.org/fedora:30 python3 build.py
$ sudo dnf install -y ./rpmbuild/RPMS/x86_64/silverkube*.rpm
```

* Build the silverkube image

```shell
$ buildah bud -f Containerfile -t silverkube .
```

Usage
-----

* Start the services

```shell
$ sudo mount /tmp
$ sudo silverkube start
Creating silverkube-etcd
active
Creating silverkube-kube-apiserver
active
Creating silverkube-kube-controller-manager
active
Creating silverkube-kube-scheduler
active
Creating silverkube-crio
active
Creating silverkube-kubelet
active
up!
Creating namespace
namespace/fedora unchanged
serviceaccount/fedora configured
export KUBECONFIG=/var/lib/silverkube/kubeconfig.user
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

* implement a tool to start applications from the desktop environment
* add security context to prevent privilege escallation

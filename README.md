Silverkube - a kubernetes service for desktop
=============================================

The goal is to provide a kubernetes service suitable to manage
a desktop workstation:

* Minimal services to be started early.
* Basic auth enough to let a container starts more containers.

This process is pretty much an experimental work in progress,
use at your own risk.

Demo video: [https://youtu.be/w86Dp5D8Xag](https://youtu.be/w86Dp5D8Xag)


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
$ mkdir -p ~/.cache/silverkube
$ podman run --rm -it \
  -v $HOME/.cache/silverkube:/root/.cache/silverkube:Z \
  -v $(pwd):/data:Z --workdir /data \
  registry.fedoraproject.org/fedora:30 python3 build.py
$ sudo dnf install -y ./rpmbuild/RPMS/x86_64/silverkube*.rpm
```

* Build the silverkube image

```shell
# Use vfs-storage for rootless crio
$ buildah --storage-driver vfs --root $HOME/.local/share/silverkube/storage/ \
    --runroot /tmp/1000  bud -f Containerfile -t silverkube desktop
```

Usage
-----

* Start the services

```shell
$ sudo mount /tmp
$ silverkube start
Starting silverkube-rootlesskit
Starting silverkube-crio
Starting silverkube-etcd
Starting silverkube-kube-apiserver
Starting silverkube-kube-controller-manager
Starting silverkube-kube-scheduler
Starting silverkube-kubelet
Checking silverkube-rootlesskit
active
Checking silverkube-crio
active
Checking silverkube-etcd
active
Checking silverkube-kube-apiserver
active
Checking silverkube-kube-controller-manager
active
Checking silverkube-kube-scheduler
active
Checking silverkube-kubelet
active
up!
namespace/fedora created
serviceaccount/fedora created
alias kubectl='/home/fedora/.local/bin/rootless-join kubectl --config /home/fedora/.config/silverkube/kubeconfig.user'
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

* implement a tool such as [podenv](https://github.com/podenv/podenv) to start applications from the desktop environment.
* add security context to prevent privilege escallation.
* start kube and crio service as unprivileged user.

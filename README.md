# Silverkube - a kubernetes service for desktop

The goal is to provide a kubernetes service suitable to manage
a desktop workstation:

- Minimal services to be started early.
- Basic auth enough to let a container starts more containers.

This process is pretty much an experimental work in progress,
use at your own risk.

## Install

- On a fedora-30 system, install the pre-built package:

```shell
sudo dnf install -y $SILVERKUBE_RPM_RELEASE_URL
```

- Or build the package locally using:

```shell
python3 build.py
```

- Or build the package inside a container:

```shell
mkdir -p ~/.cache/silverkube
podman run --rm -it \
  -v $HOME/.cache/silverkube:/root/.cache/silverkube:Z \
  -v $(pwd):/data:Z --workdir /data \
  registry.fedoraproject.org/fedora:33 python3 build.py
```

## Usage

- Start the services rootless

```shell
$ silverkube start
[...]
up!
alias kubectl='/home/fedora/.local/bin/rootless-join kubectl --kubeconfig /home/fedora/.config/silverkube/kubeconfig'
```

- Or start the services as root

```shell
$ sudo silverkube start
[...]
up!
alias kubectl='kubectl --kubeconfig /etc/silverkube/kubeconfig'
```

- Stop the services using `stop` argument

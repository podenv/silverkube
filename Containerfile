FROM registry.fedoraproject.org/fedora:30
RUN dnf install -y acl attr basesystem bash file pciutils which time \
  bind-utils tcpdump bc bzip2 gnupg2 htop less lsof man-db man-pages \
  nmap-ncat procps-ng psmisc strace sudo tar tree unzip vim-enhanced \
  alsa-utils glx-utils pinentry-gtk \
  pulseaudio xorg-x11-xauth xorg-x11-drv-vesa xorg-x11-drv-evdev \
  xorg-x11-drv-fbdev xorg-x11-drv-intel xorg-x11-drv-libinput \
  xorg-x11-drv-qxl xorg-x11-drv-vesa xorg-x11-utils  xorg-x11-xkb-utils \
  xterm xorg-x11-server-Xspice pulseaudio pavucontrol xmonad git

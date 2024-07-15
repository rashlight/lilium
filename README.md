# Lilium

*a project to unify programs and libraries*

## About

The Lilium Project is a solution to run many versions of programs and libraries together.

## Prerequisites

 - To run, any recently new Linux kernel will works, kernel version 3.6.0 and above.
 - Depending on the distribution, the kernel headers package is required for development. Consult your distribution's help for more information.

## Installation 

For normal usage, DKMS (Dynamic Kernel Module Support) configuration is included and is the recommended method:

```bash
git clone https://github.com/rashlight/lilium.git
cd lilium
sudo dkms add .
sudo dkms build lilium-module -v 1.0
sudo dkms install --force lilium-module -v 1.0
```

For development:

```bash
git clone https://github.com/rashlight/lilium.git
cd lilium
sudo make
sudo insmod lilium.ko
```

## Legal

The LICENSE file contains more information about each part of the project's licenses.
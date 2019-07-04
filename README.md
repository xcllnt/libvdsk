# libvdsk
Library for working with and on virtual disks

The library supports using RAW and QCOW2 files with support for QCOW2 backing
files.

This repo also includes bhyve as a proof of concept of how to use the libvdsk
API.

Installation:
-------------
```
make && make install
```

This installs bhyve together with libvdsk.

This overrides you bhyve install, and it is used like regular bhyve.

   __
\ (..) /           ▄    █            ▀▀█    █
 \ mm /    ▄▄▄   ▄▄█▄▄  █ ▄▄   ▄   ▄   █    █ ▄▄   ▄   ▄
  |  |    █▀  ▀    █    █▀  █  █   █   █    █▀  █  █   █
  |__|    █        █    █   █  █   █   █    █   █  █   █
  |  |    ▀█▄▄▀    ▀▄▄  █   █  ▀▄▄▀█   ▀▄▄  █   █  ▀▄▄▀█
  |  |

C  Container
T  Technology for
H  Hardcore
U  Users of
L  Linux that's
H  Hardcore and
U  Useful

--------------------------------------------------------

A very simple tool for starting a shell in a "container"

Demonstration use only. Designed to demonstrate:

- Namespaces
- CGroups
- Chroot
- Virtual Ethernet devices

Running ./cthulhu (as root) will

- Dial up alllll the namespaces
- Set up a veth pair with IP 10.0.0.1 (host) and 10.0.0.2 (container)
  This part needs some work due to some netlink behaviour I haven't quite had time to work through. 
  You can manually configure an IP in the container, though, and it works.
- Mount-namespace (chroot) the contained process to the "chroot" directory in cwd -
  To populate your chroot, run something like `debootstrap xenial chroot`
  This will be your container filesystem.

To build, run `./build.sh`. You'll need the libraries mentioned in that file.
All sources are in `cthulhu.c`

Happy namespace abuse!

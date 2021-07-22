set -eux

make-kpkg --rootcmd fakeroot --append-to-version -kcov --revision 0.6 --initrd --jobs 8 kernel_image kernel_headers

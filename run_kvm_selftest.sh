set -eux

sudo make -C tools/testing/selftests/ TARGETS=kvm run_tests

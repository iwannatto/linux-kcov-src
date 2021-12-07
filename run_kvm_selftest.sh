set -eux

mkdir -p ./selftest-coverage

# build
# clean is for applying changes on coverage.h
make -C tools/testing/selftests/ TARGETS=kvm clean
make -C tools/testing/selftests/ TARGETS=kvm
# run
sudo make -C tools/testing/selftests/ TARGETS=kvm run_tests

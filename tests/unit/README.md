# Unit Tests

This directory contains unit tests for accel-pppd components.
Since the project does not have a native C unit test framework integration, these tests are standalone C files.

## Running Tests

A standalone Makefile is provided to build and run the tests.

```bash
cd tests/unit
make test
```

To clean up:
```bash
make clean
```

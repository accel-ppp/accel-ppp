CC = gcc
CFLAGS = -Wall -g -I../../accel-pppd -I../../accel-pppd/triton -Istubs
LIBS = -lpcre2-8

# Add new tests here
TARGETS = test_utils_regex

all: $(TARGETS)

test_utils_regex: test_utils_regex.c ../../accel-pppd/utils.c stubs/log_stubs.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

test: all
	@for t in $(TARGETS); do \
		echo "Running $$t..."; \
		./$$t || exit 1; \
	done

clean:
	rm -f $(TARGETS)

.PHONY: all test clean


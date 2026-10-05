.PHONY: kernelrelease modules modules_install

kernelrelease:
	@printf '%s\n' test-kernel

modules:
	@module=$$(basename "$$(dirname "$(M)")"); \
	printf 'test module %s\n' "$$module" > "$(M)/$$module.ko"

modules_install:
	@test "$(M)" != ""
	@test -d "$(M)"
	@if test "$${FAIL_MODULES_INSTALL:-0}" = 1; then exit 42; fi
	@module=$$(basename "$$(dirname "$(M)")"); \
	test -f "$(M)/$$module.ko"; \
	destination="$(INSTALL_MOD_PATH)/lib/modules/test-kernel/extra"; \
	mkdir -p "$$destination"; \
	cp "$(M)/$$module.ko" "$$destination/$$module.ko"

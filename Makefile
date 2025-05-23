install:
	clib install --dev --concurrency 1

test:
	@$(CC) $(CFLAGS) test.c -I src -I deps $(LDFLAGS) -o $@
	@./$@

.PHONY: test

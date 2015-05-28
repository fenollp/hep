all: app

-include erl.mk
# Your targets after this line.

## Example:
test: eunit
debug: debug-app
clean: clean-ebin

.PHONY: test debug clean

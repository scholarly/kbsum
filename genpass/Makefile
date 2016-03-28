
SRC := $(wildcard *.c)
HDR := $(wildcard *.h)
OBJ := $(SRC:.c=.o)

all: genpass

genpass: $(OBJ)
	$(CC) $(CFLAGS) $^ -o$@
clean:
	-rm -f genpass $(OBJ)
indent:
	indent -linux -l300 -brf *.[ch]

.PHONY: clean indent all options

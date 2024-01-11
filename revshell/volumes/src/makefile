all: simple_loop.bin simple_prompt.bin

.PHONY: all clean

simple_loop.bin: simple_loop.o
	gcc -o $@ $^

simple_prompt.bin: simple_prompt.o
	gcc -o $@ $^

clean:
	rm -rf *.bin *.o


CC=sudo gcc
INCLUDE_DIR=include
BUILD_DIR=build
SRC_DIR=src
CFLAGS=-I$(INCLUDE_DIR) -g

SRC=$(wildcard *.c $(SRC_DIR)/*.c)
OBJ=$(patsubst %.c,$(BUILD_DIR)/%.o,${SRC})

$(BUILD_DIR)/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) -c -o $@ $< $(CFLAGS)

netscan: $(OBJ)
	$(CC) -o $@ $(OBJ) $(CFLAGS)
	sudo chmod u+s $@

clean: 
	rm -rf $(BUILD_DIR) netscan

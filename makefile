CC		:= gcc
LD		:= gcc

SRC_DIR		:= ./src
INCDIR 		:= ./include
BIN_DIR		:= ./bin

SRC_FILES 	:= $(wildcard $(SRC_DIR)/*.c)
OBJS_FILES      := $(patsubst %.c,%.o,$(SRC_FILES))
BIN_FILES	:= $(patsubst %.c,%,$(SRC_FILES))

LD_FLAGS	:= -L $(LIB_SSL_PATH) -lssl -L $(LIB_CRYPTO_PATH) -lcrypto
INC_FLAGS       := -I $(INCDIR)


all: $(OBJS_FILES) $(BIN_FILES)

$(OBJS_FILES):%.o: %.c
	$(CC) $(INC_FLAGS) -c $< -o $(SRC_DIR)/$(@F)

$(BIN_FILES):%: %.o
	$(LD) -o $(BIN_DIR)/$(@F) $< $(LD_FLAGS)


clean :
	rm $(SRC_DIR)/*.o
	rm $(BIN_DIR)/*

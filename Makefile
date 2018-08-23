#created by lijk<lijk@infosec.com.cn>
ifndef CC
CC := cc
endif
CFLAGS := -g -O0 -Wall -fPIC
CFLAGS += -D__DEBUG__
CFLAGS += -I./
LDFLAGS += -L./
LIBS += -ldl

.PHONY : default all clean

SRCS += arp.c

OBJS = $(SRCS:.c=.o)

TARGET = arp

default : all

all : ${TARGET}

${TARGET} : ${OBJS}
	${CC} -o $@ ${OBJS} ${LDFLAGS} ${LIBS}
	@echo "$@"

%.o : %.c %.h
	${CC} ${CFLAGS} -o $@ -c $<

clean :
	rm -rf ${OBJS} ${TARGET}

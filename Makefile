
CC=		/usr/bin/gcc

PROG=		tnm
TOOL=		tnmctl

PROG_SRC=	./src/
TOOL_SRC=	./tool/
LIB=		./lib/

PROG_CSOURCE=	$(PROG_SRC)main.c	\
		$(PROG_SRC)nm.c		\
		$(PROG_SRC)command.c	\
		$(PROG_SRC)host.c	\
		$(PROG_SRC)icmp.c	\
		$(PROG_SRC)misc.c	\
		$(PROG_SRC)db.c		\
		$(PROG_SRC)mongo.c	\
		$(PROG_SRC)db_file.c	\
		$(LIB)nm_common.c	\
		$(LIB)sock.c		\
		$(LIB)http.c		\
		$(LIB)file_utils.c	\
		$(LIB)log.c		\
		$(LIB)mem.c		\
		$(LIB)str.c		\
		$(LIB)progname.c	\
		$(LIB)sbuf.c		\
		$(LIB)uuid.c		\
		$(LIB)json_utils.c	\
		$(LIB)cJSON.c

TOOL_CSOURCE=	$(TOOL_SRC)main.c

PROG_OBJS=	$(PROG_CSOURCE:.c=.o)
TOOL_OBJS=	$(TOOL_CSOURCE:.c=.o)

CFLAGS=		-g2 -O0 -W -Wall -Wextra -pedantic -Wpedantic -std=c11 \
		-Wbad-function-cast -Wcast-align -Wcast-qual \
		-Wconversion -Wdate-time -Wfloat-equal \
		-Wformat=2 -Winit-self -Wnested-externs \
		-Wnull-dereference -Wold-style-definition \
		-Wpointer-arith -Wshadow -Wstack-protector \
		-Wstrict-prototypes -Wswitch-default -Wwrite-strings  \
		-Wmissing-prototypes -Wformat-security -fstack-protector-strong \
		-Wduplicated-cond -Wformat-signedness -Wjump-misses-init -Wlogical-op \
		-Wnormalized -Wsuggest-attribute=format \
		-Wtrampolines -pie -fPIE \
		-D_FORTIFY_SOURCE=2 \
		-D_GNU_SOURCE \
		-DHAVE_SSL -DHAVE_MONGOC \
		-D_XOPEN_SOURCE=700 \
		-DENABLE_CJSON_TEST=Off \
		-DENABLE_CJSON_UTILS=On

LDFLAGS= -Isrc/ -lssl -lcrypto -I/usr/include/libbson-1.0 -I/usr/include/libmongoc-1.0 -lmongoc-1.0 -lbson-1.0 #$(pkg-config --libs --cflags libmongoc-1.0)

all:		$(PROG) #$(TOOL)

$(PROG):	$(PROG_OBJS)
		$(CC) -o $@ $(PROG_OBJS) $(LDFLAGS) -lpthread

$(TOOL):	$(TOOL_OBJS)
		$(CC) -o $@ $(TOOL_OBJS) $(LDFLAGS)

.c.o:
		$(CC) $(CFLAGS) $(LDFLAGS) -o $@ -c $<

.PHONY: clean  distclean install uninstall re all release debug clang val r d

clang:		CC=/usr/bin/clang
clang:		CFLAGS=-I src/ -W -Wall -Wextra -pedantic -Wpedantic -std=c11 \
		       	-Wbad-function-cast -Wcast-align -Wcast-qual \
			-Wconversion -Wdate-time -Wfloat-equal \
			-Wformat=2 -Winit-self -Wnested-externs \
			-Wnull-dereference -Wold-style-definition \
			-Wpointer-arith -Wshadow -Wstack-protector \
			-Wstrict-prototypes -Wswitch-default -Wwrite-strings  \
			-Wmissing-prototypes -Wformat-security -fstack-protector-strong \
			-pie -fPIE \
			-DHAVE_SSL -DHAVE_MONGOC \
			-D_FORTIFY_SOURCE=2 \
			-D_GNU_SOURCE -D_XOPEN_SOURCE=700 \
			-DENABLE_CJSON_UTILS=On -DENABLE_CJSON_TEST=Off
clang:		all

debug:		CFLAGS += -g2 -O0
debug:		all

release: 	CFLAGS += -DNDEBUG -O2
release:	all

r:		release
d:		debug
v:              valgrind

install:
		@echo "install $(PROG) in /usr/bin/ ..."
		cp $(PROG) /usr/bin
		@echo "install $(TOOL) in /usr/bin/ ..."
		cp $(TOOL) /usr/bin

uninstall:
		@echo "delete $(PROG) in /usr/bin/ ..."
		@rm /usr/bin/$(PROG)
		@echo "delete $(TOOL) in /usr/bin/ ..."
		@rm /usr/bin/$(TOOL)

clean:
		@rm ./*~ ./*/*~ ./*/*.o; 2>/dev/null


distclean:
		@-rm $(TOOL) $(PROG)

re:		clean distclean all

valgrind:
		valgrind --leak-check=full --show-leak-kinds=all ./$(PROG)

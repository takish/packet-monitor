PACKAGE	= pkt_monitor
CC = gcc
CFLAGS = -O2 -g -W -Wall -Wwrite-strings -Wbad-function-cast -Wmissing-prototypes -Wcast-qual -Wmissing-declarations -Werror
LFLAGS = -lnsl

SRCS = $(OBJS:%.o=%.c)
HEADERS	= 
OBJS	= pkt_monitor.o
FILES	= Makefile $(HEADERS) $(SRCS) .package_ver
VER	= `date +%y%m%d`
RM	= rm -f

all: $(PACKAGE)

$(PACKAGE): $(OBJS)
	$(CC) -o $(PACKAGE) $(OBJS) $(CFLAGS) $(LFLAGS)

$(OBJS): $(SRCS) $(HEADERS)
	$(CC) -c $(SRCS)

clean:
	$(RM) $(PACKAGE) $(OBJS)
	$(RM) core gmon.out *~ #*#

tar:
	@echo $(PACKAGE)-$(VER) > .package_ver
	@echo $(PACKAGE) > .package
	@$(RM) -r `cat .package`
	@mkdir `cat .package`
	@ln $(FILES) `cat .package`
	tar cvf - `cat .package` | gzip -9 > `cat .package_ver`.tar.gz
	@$(RM) -r `cat .package` .package

install:
	cp $(PACKAGE) /usr/local/bin/
	chmod u+s /usr/local/bin/$(PACKAGE)

# DO NOT DELETE

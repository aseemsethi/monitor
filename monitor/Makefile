#
# Makefile for mont program
#

# Parameters
INSTDIR = ../monitor/bin
MONT = mont_cust
CFLAGS = -g
LEX = lex

#	$(wildcard common/*.c)  \

csrc = $(wildcard ssl/*.c)  \
	common/log.c common/mont_cust.c common/parser.c \
	$(wildcard ssl_perf/*.c) \
	$(wildcard http/*.c) \
	$(wildcard ikev2/*.c) \
	$(wildcard openvpn/*.c) \
	$(wildcard bgp/*.c) 


obj = $(csrc:.c=.o)

LDFLAGS = -L../bin -ljsmn -lexpat -lpthread -lcrypto -lssl -lcurl

# Targets 
all : $(MONT)

$(MONT): $(obj)
	$(LEX) -o common/lex.yy.c common/cli.l
	gcc -c -o common/lex.yy.o common/lex.yy.c
	$(CXX) -g -o $@ $^ common/lex.yy.o $(LDFLAGS)
#	$(CXX) -g -o $@ $^ $(LDFLAGS)


clean:
	$(RM) core* ssl/*.o ssl_perf/*.o http/*.o bgp/*.o common/*.o \
		ikev2/*.o openvpn/*.o mont_cust common/lex.yy.c

install:
	cp $(MONT) ${INSTDIR}

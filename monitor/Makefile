#
# Makefile for mont program
#

# Parameters
INSTDIR = /home/asethi/monitor/bin
MONT = mont_cust
CFLAGS = -g

csrc = $(wildcard ssl/*.c)  \
	$(wildcard common/*.c)  \
	$(wildcard ssl_perf/*.c) \
	$(wildcard http/*.c) \
	$(wildcard ikev2/*.c) 

obj = $(csrc:.c=.o)

LDFLAGS = -L../bin -lxmlparse -lexpat -lpthread -lssl -lcurl

# Targets 
all : $(MONT)

$(MONT): $(obj)
	$(CXX) -g -o $@ $^ $(LDFLAGS)

clean:
	$(RM) core* ssl/*.o ssl_perf/*.o mont_cust

install:
	cp $(MONT) ${INSTDIR}

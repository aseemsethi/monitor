#
# Makefile for mont program
#

# Parameters
INSTDIR = /home/asethi/monitor/bin
MONT = mont_cust

csrc = $(wildcard ssl/*.c)  \
	$(wildcard common/*.c) 

obj = $(csrc:.c=.o)

LDFLAGS = -L../bin -lxmlparse -lexpat -lpthread

# Targets 
all : $(MONT)

$(MONT): $(obj)
	$(CXX) -o $@ $^ $(LDFLAGS)

clean:
	$(RM) core* *.o MONT

install:
	cp $(MONT) ${INSTDIR}

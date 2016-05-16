INSTDIR = /home/asethi/monitor/bin

all:
	(cd jsmn; make all)
	(cd monitor; make all)
install:
	(cd monitor; make install INSTDIR=${INSTDIR})
clean:
	(cd monitor; make clean)
	(cd bin; make clean)

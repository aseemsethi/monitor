INSTDIR = /home/asethi/mont/bin

all:
	(cd monitor/xmlparser; make all)
	(cd monitor; make all)
install:
	(cd monitor/xmlparser; make install INSTDIR=${INSTDIR})
	(cd monitor; make install INSTDIR=${INSTDIR})
clean:
	(cd monitor; make clean)
	(cd monitor/xmlparser; make clean)
	(cd bin; make clean)

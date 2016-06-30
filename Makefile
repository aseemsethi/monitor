INSTDIR = ./bin

all:
	(cd jsmn; make all)
	(cd monitor; make)
install:
	(cd monitor; make install INSTDIR=${INSTDIR})
clean:
	(cd monitor; make clean)
	(cd bin; make clean)

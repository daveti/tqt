# Make for tqt
# Sep 13, 2013
# root@davejingtian.org
# http://davejingtian.org

CC=gcc
CFLAGS=-I.
LIBS=-lcurl -ltspi -lcrypto

all: identity getaikpub aikquote

identity: identity.o
	$(CC) -o identity identity.o $(CFLAGS) $(LIBS)

getaikpub: getaikpub.o
	$(CC) -o getaikpub getaikpub.o $(CFLAGS) $(LIBS)

aikquote: aikquote.o
	$(CC) -o aikquote aikquote.o $(CFLAGS) $(LIBS)

clean:
	rm -rf identity \
		getaikpub \
		aikquote \
		*.o

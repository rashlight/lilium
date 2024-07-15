VERSION = 6
PATCHLEVEL = 9
SUBLEVEL = 5
EXTRAVERSION = 200.fc40.x86_64

obj-m += lilium.o

PWD := $(CURDIR)

all: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

debug:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 
	EXTRA_CFLAGS="$(MY_CFLAGS)"

clean: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

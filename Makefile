LDFLAG=-lusb-1.0 -pthread -ljsoncpp
CFLAGS += -I/usr/include/crow

ifndef CFLAGS
	ifeq ($(TARGET),Debug)
		CFLAGS=-Wall -Wextra -g
	else
		CFLAGS=-Wall -Wextra -O2
	endif
endif

# List of source files
SRC_FILES = usb-proxy.cpp host-raw-gadget.cpp device-libusb.cpp proxy.cpp misc.cpp letter_mapping.cpp WebServer.cpp

# Corresponding object files
OBJ_FILES = $(SRC_FILES:.cpp=.o)

# Main target
usb-proxy: $(OBJ_FILES)
	g++ $(OBJ_FILES) $(LDFLAG) -o usb-proxy

# Pattern rule to compile source files to object files
%.o: %.cpp %.h
	g++ $(CFLAGS) -c $<

%.o: %.cpp
	g++ $(CFLAGS) -c $<

clean:
	-rm *.o
	-rm usb-proxy

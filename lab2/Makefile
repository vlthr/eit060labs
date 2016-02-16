CC=gcc
CFLAGS=-c -Wall
LDFLAGS=-lcrypt
#SOURCES=mylogin.c openshell_demo.c pwdblib.c update_user.c userinfo.c
SOURCES=mylogin.c pwdblib.c # openshell_demo.c update_user.c userinfo.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=mylogin

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

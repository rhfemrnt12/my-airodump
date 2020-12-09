LDLIBS=-lpcap

all: airodump

airodump: main.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

main.o: airodump.cpp
	g++ -c -o main.o airodump.cpp -lpcap
clean:
	rm -f airodump *.o

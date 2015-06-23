all: out_files

out_files: o_files
	g++ -o server.out -O2 server.o crypto.o encodings.o -lssl
	g++ -o client.out -O2 client.o crypto.o encodings.o -lssl

o_files: 
	g++ -c -O2 server.cpp
	g++ -c -O2 client.cpp


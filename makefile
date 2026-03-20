all: copy compile clear

copy: 
	cp  lib/* build/ && cp include/* build/ && cp src/* build/ 

compile: 
	cd build && g++ -std=c++20 main.cpp csync.cpp -L. -lwirelink -o test

clear: 
	cd build && rm -rf *.a && rm -rf *.h && rm -rf *.cpp
all : 
	gcc -Wno-stringop-overflow -no-pie -fno-stack-protector -o ropme ropme.c 


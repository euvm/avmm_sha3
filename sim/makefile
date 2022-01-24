CC              = gcc
CFLAGS		= -Wall -O3 -fPIC
INCLUDES        = -I ../testbench/tiny_sha3

DEBUG = NONE

DFLAGS = -relocation-model=pic -w -O3 -lowmem -release -boundscheck=off

all: avmm_sha3.vvp avmm_sha3.vpi

clean:
	rm -f avmm_sha3.vvp avmm_sha3.vpi avmm_sha3.o avmm_sha3.vcd sha3.o libsha3.a

run: avmm_sha3.vvp avmm_sha3.vpi
	vvp -M. -mavmm_sha3 avmm_sha3.vvp +UVM_TESTNAME=avmm_sha3.random_test # +UVM_OBJECTION_TRACE # +UVM_VERBOSITY=DEBUG

avmm_sha3.vvp: ../testbench/avmm_sha3.v ../src/rtl/*.v
	iverilog -o $@ $^

quartus_compile: ../testbench/avmm_sha3.v ../src/rtl/*.v
	rm -rf work
	vlib work
	vlog $^

avmm_sha3.vpi: ../testbench/avmm_sha3.d libsha3.a
	ldc2 $(DFLAGS) -shared -of$@ -L-luvm-ldc-shared -L-lesdl-ldc-shared \
		-L-lphobos2-ldc-shared -L-lz3 -L-ldl $^

avmm_sha3.so: ../testbench/avmm_sha3.d libsha3.a
	ldc2 $(DFLAGS) -shared -of$@ -L-luvm-ldc-debug-shared -L-lesdl-ldc-debug-shared \
		-L-lphobos2-ldc-shared -L-ldl $^
	objcopy -N _Unwind_DeleteException \
		-N _Unwind_GetLanguageSpecificData \
		-N _Unwind_GetIPInfo \
		-N _Unwind_GetRegionStart \
		-N _Unwind_Resume \
		-N _Unwind_SetGR \
		-N _Unwind_SetIP \
		-N _Unwind_RaiseException $@


vsim: avmm_sha3.so quartus_compile 
	vsim -c -pli $< sha3_tb +UVM_TESTNAME=avmm_sha3.random_test \
	-dpicpppath /usr/bin/gcc -do "run -all; q"


libsha3.a: sha3.o
	ar r $@ $^

sha3.o: ../testbench/tiny_sha3/sha3.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

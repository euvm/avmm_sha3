DEBUG = NONE

DFLAGS = -relocation-model=pic -w -O3 -lowmem -release -boundscheck=off

all: avmm_sha3.vvp avmm_sha3.vpi

clean:
	rm -f avmm_sha3.vvp avmm_sha3.vpi avmm_sha3.o avmm_sha3.vcd
	cd tiny_sha3; make clean

run: avmm_sha3.vvp avmm_sha3.vpi
	vvp -M. -mavmm_sha3 avmm_sha3.vvp +UVM_TESTNAME=avmm_sha3.random_test # +UVM_OBJECTION_TRACE # +UVM_VERBOSITY=DEBUG

avmm_sha3.vvp: avmm_sha3.v ../rtl/*.v
	iverilog -o $@ $^

avmm_sha3.vpi: avmm_sha3.d tiny_sha3/libsha3.a
	ldc2 $(DFLAGS) -shared -of$@ -L-luvm-ldc-shared -L-lesdl-ldc-shared \
		-L-lphobos2-ldc-shared -L-ldl $^

tiny_sha3/libsha3.a:
	cd tiny_sha3; make lib

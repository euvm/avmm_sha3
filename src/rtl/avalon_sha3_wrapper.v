module avalon_sha3_wrapper
  (
   clk, // clock.clk
   reset, // reset.reset

   // Memory mapped read/write slave interface
   avs_s0_address,
   avs_s0_read,
   avs_s0_write,
   avs_s0_writedata,
   avs_s0_readdata,
   avs_s0_waitrequest
   );

   input	 clk; // clock.clk
   input	 reset; // reset.reset

   // Memory mapped read/write slave interface
   input [7:0] 	 avs_s0_address;
   input	 avs_s0_read;
   input	 avs_s0_write;
   input [31:0]  avs_s0_writedata;
   output [31:0] avs_s0_readdata;
   output	 avs_s0_waitrequest;

   wire [31:0] 	 avs_s0_readdata;

   wire		 avs_s0_waitrequest;

   wire		 rst_n;
   reg		 state_read;
   wire		 cs;
   wire		 we;
   reg [31:0] 	 write_data;
   wire [31:0] 	 read_data;
   wire		 reg_status_valid;

   assign rst_n = ~reset;

   assign cs = (avs_s0_read || avs_s0_write);
   assign we = avs_s0_write;
   assign avs_s0_waitrequest = ~reg_status_valid && avs_s0_read;


   sha3_wrapper sha3_wr (.clk              (clk),
			 .rst_n            (rst_n),
			 .cs               (cs),
			 .we               (we),
			 .address          (avs_s0_address),
			 .write_data       (avs_s0_writedata),
			 .read_data        (avs_s0_readdata),
			 .reg_status_valid (reg_status_valid)
			 );
endmodule // avalon_sha3_wrapper

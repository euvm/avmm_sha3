`timescale 1ns/100ps

module sha3_tb();

   /*AUTOWIRE*/
   // Beginning of automatic wires (for undeclared instantiated-module outputs)
   wire [31:0]		avs_s0_readdata;	// From u_sha3 of avalon_sha3.v
   wire			avs_s0_waitrequest;	// From u_sha3 of avalon_sha3.v
   // End of automatics
   
   /*AUTOREGINPUT*/
   // Beginning of automatic reg inputs (for undeclared instantiated-module inputs)
   reg [7:0] 		avs_s0_address;		// To u_sha3 of avalon_sha3.v
   reg			avs_s0_read;		// To u_sha3 of avalon_sha3.v
   reg			avs_s0_write;		// To u_sha3 of avalon_sha3.v
   reg [31:0] 		avs_s0_writedata;	// To u_sha3 of avalon_sha3.v
   // reg 			avs_s0_chipselect;      //			
   reg			clk;			// To u_sha3 of avalon_sha3.v
   reg			reset;			// To u_sha3 of avalon_sha3.v
   // End of automatics
   
   initial begin
      reset = 0;
      #10;
      reset = 1;
      #100;
      reset = 0;
      // #1000000;
      // $finish;
   end
   

   initial begin
      clk = 0;
      forever begin
	 #10;
	 clk = ~clk;
      end
   end

   task write(input [7:0]  addr,
	      input [31:0] data);
      begin
	 @(negedge clk);
	 avs_s0_address = addr;
	 avs_s0_writedata = data;
	 avs_s0_write = 1;
	 avs_s0_read = 0;
	 // avs_s0_chipselect = 0;
	 @(posedge clk);
      end
   endtask // write


   task read(input [7:0] addr);
      begin
	 @(negedge clk);
	 avs_s0_address = addr;
	 avs_s0_read = 1;
	 avs_s0_write = 0;
	 // avs_s0_chipselect = 0;
	 @(posedge clk);
      end
   endtask
   
   task idle;
      @(negedge clk);
   endtask

   initial begin: bfm
      reg [9:0]  addr;
      reg [31:0] data;
      reg [3:0]  strb;
      reg 	 flag;
      #200;
      @(posedge clk);
      forever begin
	 while (reset == 1'b1) begin
	    @(posedge clk);
	 end // while (reset == 1'b1)
	 
	 case ($avl_try_next_item(addr, strb, data, flag))
	   0: begin: valid_transaction
	      if (flag == 1) begin	// write
		 write (addr/4, data);
	      end // if (flag == 1)
	      else begin
		 read (addr/4);
	      end
	      while (avs_s0_waitrequest) begin
		 @(posedge clk);
	      end
	      @(negedge clk);
	      if (flag == 0) data = avs_s0_readdata;
	      avs_s0_address = 'bX;
	      avs_s0_read = 0;
	      avs_s0_writedata = 'bX;
	      avs_s0_write = 0;
	      // avs_s0_chipselect = 0;
	      if ($avl_item_done(0) != 0) ; // $finish;
	      if ($avl_put(addr, strb, data, flag) != 0) begin
		 // $finish;
	      end
	   end // block: valid_tr
	   default: begin: idle_transaction
	      @(negedge clk);
	      avs_s0_read = 1'b0;
	      avs_s0_write = 1'b0;
	      @(posedge clk);
	   end
	   // default: ; // $finish;
	 endcase
	 
      end // forever begin
   end // initial begin
   
   
   initial
   begin
      $dumpfile("avmm_sha3.vcd");
      $dumpvars(0, sha3_tb);
   end // initial begin
   
   avalon_sha3_wrapper u_sha3(/*AUTOINST*/
			      // Outputs
			      .avs_s0_readdata	  (avs_s0_readdata[31:0]),
			      .avs_s0_waitrequest (avs_s0_waitrequest),
			      // Inputs
			      .clk		  (clk),
			      .reset		  (reset),
			      // .avs_s0_chipselect  (avs_s0_chipselect),
			      .avs_s0_address	  (avs_s0_address[7:0]),
			      .avs_s0_read	  (avs_s0_read),
			      .avs_s0_write	  (avs_s0_write),
			      .avs_s0_writedata	  (avs_s0_writedata[31:0]));
endmodule


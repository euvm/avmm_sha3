import esdl;
import uvm;
import std.stdio;
import std.string: format;

extern(C) void* sha3(const void* str, size_t strlen, void* md, int mdlen);

enum output_size_enum {SHA3_224=224, SHA3_256=256,
		       SHA3_384=384, SHA3_512=512}

enum access_enum: bool {READ, WRITE}

class sha3_seq_item: uvm_sequence_item
{
  mixin uvm_object_utils;
  this(string name="") {
    super(name);
  }

  @UVM_DEFAULT {
    access_enum type;
    @rand ubyte[] phrase;
    @rand output_size_enum out_size;
  }
  Constraint! q{
    phrase.length <= 1024;
    foreach (c; phrase) {
      c < 80;
      c > 10;
    }
  } phrase_length;
}

class sha3_sequence: uvm_sequence!sha3_seq_item
{
  mixin uvm_object_utils;
  sha3_sequencer sequencer;
  output_size_enum out_size;
  string phrase;

  void set_phrase(string ph) {
    phrase = ph;
  }

  void set_outputsize(output_size_enum os) {
    out_size = os;
  }
  
  this(string name = "sha3_sequence") {
    super(name);
    req = REQ.type_id.create("req");
  }

  override void body() {
    for (size_t i=0; i!=1; ++i) {
      // req.phrase = cast(ubyte[]) phrase;
      // req.out_size = cast(output_size_enum) out_size;
      req.randomize();
      // writeln("Seed was: ", req._esdl__getRandomSeed());
      // writeln("Proc Seed was: ", Process.self.getRandSeed());
      // writeln("Proc Name was: ", Process.self.getFullName());
      uvm_info("PRINTREQUEST", ":\n" ~ req.sprint(), UVM_DEBUG);
      req.type = access_enum.WRITE;
      REQ tr = cast(REQ) req.clone;
      start_item(tr);
      finish_item(tr);
    }
  }
}

class sha3_sequencer:  uvm_sequencer!sha3_seq_item
{
  mixin uvm_component_utils;

  this(string name, uvm_component parent=null) {
    super(name, parent);
  }
}

class sha3_agent: uvm_agent
{
  mixin uvm_component_utils;

  @UVM_BUILD sha3_sequencer  sequencer;

  this(string name, uvm_component parent) {
    super(name, parent);
  }
}

class avl_seq_item(int DW, int AW): uvm_sequence_item
{
  mixin uvm_object_utils;
  
  this(string name="") {
    super(name);
  }
  
  enum BW = DW/8;

  @UVM_DEFAULT {
    @rand UBit!AW addr;
    @rand Bit!DW  data;
    @rand access_enum type;
    @UVM_BIN			// print in binary format
      @rand UBit!BW strb;
  }

  Constraint! q{
    (addr >> 2) < 4;
    addr % BW == 0;
  } addrCst;

  override void do_vpi_put(uvm_vpi_iter iter) {
    iter.put_values(addr, strb, data, type);
  }

  override void do_vpi_get(uvm_vpi_iter iter) {
    iter.get_values(addr, strb, data, type);
  }
};

class sha3_avl_sequence(int DW, int AW): uvm_sequence!(avl_seq_item!(DW, AW))
{
  mixin uvm_object_utils;
  avl_sequencer!(DW,AW) sequencer;
  sha3_seq_item sha3_item;

  this(string name = "sha3_avl_sequence") {
    super(name);
  }

  override void body() {
    sequencer.sha3_get_port.get(sha3_item);
    auto data = sha3_item.phrase;
    auto size = sha3_item.out_size;
    bool last_block = false;
    uint rate = (1600-2*size)/8; // 144, 136, 104, 72
    uint num_frames = cast(uint) (((data.length + rate))/(rate));
    for (size_t k=0; k!=num_frames; ++k) {
      ubyte [200] arr_block;
      for (size_t i=0; i!=rate; ++i) {
	if (k*rate + i < data.length) {
	  arr_block[i] = data[rate*k+i];
	}
	else if (k*rate + i == data.length) {
	  arr_block[i] = 0x06;
	  last_block = true;
	}
	else {
	  arr_block[i] = 0x00;
	}
	if (i==(rate-1) && last_block == true) {
	  arr_block[i] |= 0x80;
	}
      }

      for (size_t i=0; i != (k==0 ? 50 : rate/4); ++i) {
	uint word = 0;
	for (size_t j=0; j!=4; ++j) {
	  word += (cast(uint) arr_block[i*4+j]) << ((j) * 8);
	}
	auto data_req = REQ.type_id.create("req");
	data_req.data = word;
	data_req.addr = cast(int) (0x200+4*i);
	data_req.strb = toBit!0xF;
	data_req.type = access_enum.WRITE;
      
	start_item(data_req);
	finish_item(data_req);
      }
      if (k == 0) {
	init_pulse();//data_req.data = 0x00000001;
      }
      else {
	next_pulse();//data_req.data = 0x00000002;
      }
    }
    read_hash(rate);
  }

  void init_pulse() {
    auto data_req = REQ.type_id.create("init_pulse_start");
    data_req.data = 0x00000001;
    data_req.addr = 0x20;
    data_req.strb = toBit!0xF;
    data_req.type = access_enum.WRITE;

    start_item(data_req);
    finish_item(data_req);

    data_req = REQ.type_id.create("init_pulse_end");
    data_req.data = 0x00000000;
    data_req.addr = 0x20;
    data_req.strb = toBit!0xF;
    data_req.type = access_enum.WRITE;

    start_item(data_req);
    finish_item(data_req);
  }

  void  next_pulse() {
    auto data_req = REQ.type_id.create("next_pulse_start");
    data_req.data = 0x00000002;
    data_req.addr = 0x20;
    data_req.strb = toBit!0xF;
    data_req.type = access_enum.WRITE;

    start_item(data_req);
    finish_item(data_req);

    data_req = REQ.type_id.create("next_pulse_end");
    data_req.data = 0x00000000;
    data_req.addr = 0x20;
    data_req.strb = toBit!0xF;
    data_req.type = access_enum.WRITE;

    start_item(data_req);
    finish_item(data_req);
  }

  void read_hash(int rate) {
    auto out_size = (1600 - rate*8)/2;
    int  num_reads = out_size/32;
    for (uint i=0; i!= num_reads; i++) {
      auto data_req = REQ.type_id.create("read_hash");
      data_req.addr = 0x300+4*i;
      data_req.strb = toBit!0xF;
      data_req.type = access_enum.READ;
    
      start_item(data_req);
      finish_item(data_req);
    }
  }
}

class avl_sequencer(int DW, int AW):
  uvm_sequencer!(avl_seq_item!(DW, AW))
{
  mixin uvm_component_utils;
  @UVM_BUILD {
    uvm_seq_item_pull_port!sha3_seq_item sha3_get_port;
  }

  this(string name, uvm_component parent=null) {
    super(name, parent);
  }
}

class avl_driver(int DW, int AW, string vpi_func):
  uvm_vpi_driver!(avl_seq_item!(DW, AW), vpi_func)
{
  enum BW = DW/8;
    
  alias REQ=avl_seq_item!(DW, AW);
  
  mixin uvm_component_utils;
  
  REQ tr;

  this(string name, uvm_component parent) {
    super(name,parent);
  }
  
  override void run_phase(uvm_phase phase) {
    super.run_phase(phase);
    get_and_drive(phase);
  }
	    
  void get_and_drive(uvm_phase phase) {
    while(true) {
      seq_item_port.get_next_item(req);
      drive_vpi_port.put(req);
      item_done_event.wait();
      seq_item_port.item_done();
    }
  }
}

class sha3_monitor(int DW, int AW): uvm_monitor
{
  sha3_seq_item sha3_item;
  
  @UVM_BUILD {
    uvm_analysis_imp!(write) avl_analysis;
    uvm_analysis_port!sha3_seq_item sha3_port;
  }

  mixin uvm_component_utils;

  this(string name, uvm_component parent) {
    super(name,parent);
  }

  union {
    uint[50] word_block;
    ubyte[200] byte_block;
  }

  ubyte[] out_buffer;

  ubyte[] sha3_buffer;

  ubyte[] sha3_str;
  
  enum sha3_state: byte {INIT_BLOCK, NEXT_BLOCK, OUT_BLOCK}

  sha3_state state;
  
  void process_transactions() {
    import std.stdio;
    uint out_size = cast(uint) (out_buffer.length * 8);
    uint blk_size = (1600 - 2*out_size)/8;
    if (out_size != output_size_enum.SHA3_224 &&
	out_size != output_size_enum.SHA3_256 &&
	out_size != output_size_enum.SHA3_384 &&
	out_size != output_size_enum.SHA3_512) {
      uvm_error("SHA3_ILLEGAL_SIZE",
		format("ILLEGAL output size %x",
		       out_size));
    }
    output_size_enum sha3_size = cast(output_size_enum) (out_size);

    for (size_t i=0; i != sha3_buffer.length/200; ++i) {
      sha3_str ~= sha3_buffer[i*200..i*200+blk_size];
      for (size_t j=i*200+blk_size; j!=(i+1)*200; ++j) {
	if (sha3_buffer[j] != 0) {
	  uvm_error("SHA3_ILLEGAL_CAPACITY_BYTE",
		    format("ILLEGAL non-zero byte in capacity region %x at position %d",
			   sha3_buffer[j], j));
	}
      }
    }

    if (sha3_str[$-1] == 0x86) {
      sha3_str.length -= 1;
    }
    else if (sha3_str[$-1] == 0x80) {
      uint i = 2;
      while (sha3_str[$-i] == 0x00) i += 1;
      if (sha3_str[$-i] != 0x06) {
	uvm_error("SHA3_ILLEGAL_PAD_START",
		  format("ILLEGAL Pas Start %x",
			 sha3_str[$-i]));
      }
      sha3_str.length -= i;
    }
    else {
      uvm_error("SHA3_ILLEGAL_LAST_BYTE",
		format("ILLEGAL Last Byte in Input %x",
		       sha3_str[$-1]));
    }
    // send transactions to scoreboard
    sha3_seq_item sha3_in_trans =
      sha3_seq_item.type_id.create("SHA3 MONITORED INPUT");
    sha3_in_trans.phrase = sha3_str;
    sha3_in_trans.out_size = sha3_size;
    sha3_in_trans.type = access_enum.WRITE;
    sha3_port.write(sha3_in_trans);
    
    sha3_seq_item sha3_out_trans =
      sha3_seq_item.type_id.create("SHA3 MONITORED OUTPUT");
    sha3_out_trans.phrase = out_buffer;
    sha3_out_trans.out_size = sha3_size;
    sha3_out_trans.type = access_enum.READ;
    sha3_port.write(sha3_out_trans);
    
    sha3_str.length = 0;
    out_buffer.length = 0;
    sha3_buffer.length = 0;
  }

  void write(avl_seq_item!(DW, AW) item) {
    if (item.type is access_enum.WRITE) { // writes on registers
      if (state is sha3_state.OUT_BLOCK) { // we have just started writing next transaction
	state = sha3_state.INIT_BLOCK;
	// process sha3_buffer and out_buffer and create input and output transactions
	this.process_transactions();
      }
      if (! (item.addr == 0x20 || (item.addr >= 0x200 && item.addr < 0x200 + 200))) {
	uvm_error("AVL_ILLEGAL_ADDR",
		  format("ILLEGAL address (%x) for AVL WRITE transaction",
			 item.addr));
      }

      if (item.addr >= 0x200) {	// register data writes
	word_block[(item.addr - 0x200)/4] = item.data;
      }

      if (item.addr == 0x20) {	// for detecting init and next
	switch (item.data) {
	case 0x00000001:
	  assert (state is sha3_state.INIT_BLOCK);
	  state = sha3_state.NEXT_BLOCK;
	  sha3_buffer ~= byte_block;
	  break;
	case 0x00000002:
	  sha3_buffer ~= byte_block;
	  break;
	case 0x00000000:
	  break;
	default:
	  uvm_error("AVL_ILLEGAL_DATA",
		    format("ILLEGAL data value (%x) observed on addr (%x)",
			   item.data, item.addr));
	  break;
	}
      }
    }
    else {			// READ in register
      state = sha3_state.OUT_BLOCK;
      if (! (item.addr >= 0x300 && item.addr < 0x300 + 16*4)) {
	uvm_error("AVL_ILLEGAL_ADDR",
		  format("ILLEGAL address (%x) for AVL READ transaction",
			 item.addr));
      }
      auto addr_offset = item.addr - 0x300;

      if (addr_offset != out_buffer.length) {
	uvm_error("AVL_ILLEGAL_ADDR",
		  format("Not in sequence address (%x) for AVL READ transaction",
			 item.addr));
      }

      uint read_data = item.data;
      ubyte* read_ptr = cast (ubyte*) &read_data;
      for (size_t i=0; i!=4; ++i) {
	out_buffer ~= read_ptr[i];
      }
    }
  }
}


class sha3_scoreboard(int DW, int AW): uvm_scoreboard
{
  mixin uvm_component_utils;

  sha3_seq_item write_seq;

  this(string name, uvm_component parent = null) {
    synchronized(this) {
      super(name, parent);
    }
  }

  uvm_phase run_ph;
  override void run_phase(uvm_phase phase) {
    run_ph = phase;
  }
  
  @UVM_BUILD {
    uvm_analysis_imp!(write) sha3_analysis;
  }
  
  ubyte[] expected;
  
  void write(sha3_seq_item item) {
    if (item.type is access_enum.WRITE) {	// req
      uvm_info("WRITE", item.sprint, UVM_DEBUG);
      write_seq = item;
      run_ph.raise_objection(this);
    }
    else {
      uvm_info("READ", item.sprint, UVM_DEBUG);
      expected.length = item.out_size/8;
      sha3(write_seq.phrase.ptr,
	   cast(uint) write_seq.phrase.length, expected.ptr, cast(uint) expected.length);
      if (expected == item.phrase) {
	uvm_info("MATCHED", format("%s: expected \n %s: actual",
				   expected, item.phrase), UVM_MEDIUM);
      }
      else {
	uvm_error("MISMATCHED", format("%s: expected \n %s: actual",
				       expected, item.phrase));
      }
      run_ph.drop_objection(this);
    }
  }

}

class sha3_env(int DW, int AW): uvm_env
{
  mixin uvm_component_utils;
  @UVM_BUILD {
    avl_agent!(DW, AW, "avl") agent;
    sha3_agent phrase_agent;
    sha3_scoreboard!(DW, AW) scoreboard;
    sha3_monitor!(DW, AW) monitor;
  }

  this(string name , uvm_component parent) {
    super(name, parent);
  }

  override void connect_phase(uvm_phase phase) {
    super.connect_phase(phase);
    monitor.sha3_port.connect(scoreboard.sha3_analysis);
    agent.monitor.rsp_port.connect(monitor.avl_analysis);
    agent.sequencer.sha3_get_port.connect(phrase_agent.sequencer.seq_item_export);
  }
}
      
class avl_agent(int DW, int AW, string VPI): uvm_agent
{
  mixin uvm_component_utils;

  @UVM_BUILD {
    avl_driver!(DW, AW, VPI)     driver;
    avl_sequencer!(DW, AW)       sequencer;
    avl_monitor!(DW, AW, VPI)    monitor;
  }

  this(string name, uvm_component parent) {
    super(name, parent);
  }

  override void connect_phase(uvm_phase phase) {
    super.connect_phase(phase);
    if (get_is_active() == UVM_ACTIVE) {
      driver.seq_item_port.connect(sequencer.seq_item_export);
    }
  }
}

class avl_monitor(int DW, int AW, string vpi_func):
  uvm_vpi_monitor!(avl_seq_item!(DW, AW), vpi_func)
{
  mixin uvm_component_utils;

  this(string name, uvm_component parent) {
    super(name, parent);
  }
}

class random_test_parameterized(int DW, int AW): uvm_test
{
  mixin uvm_component_utils;

  this(string name, uvm_component parent) {
    super(name, parent);
  }

  @UVM_BUILD {
    sha3_env!(DW, AW) env;
  }

  override void run_phase(uvm_phase  phase) {
    sha3_sequence sha3_seq;
    sha3_avl_sequence!(DW, AW) wr_seq;
    phase.raise_objection(this, "avl_test");
    phase.get_objection.set_drain_time(this, 1.usec);
    sha3_seq = sha3_sequence.type_id.create("sha3_seq");
    for (size_t i=0; i != 100; ++i) {
      fork ({
	  sha3_seq.sequencer = env.phrase_agent.sequencer;
	  sha3_seq.randomize();
	  sha3_seq.start(env.phrase_agent.sequencer);
	},
	{
	  wr_seq = sha3_avl_sequence!(DW, AW).type_id.create("wr_seq");
	  wr_seq.sequencer = env.agent.sequencer;
	  assert(wr_seq.sequencer !is null);
	  // wr_seq.randomize();
	  wr_seq.start(env.agent.sequencer);
	}).join();
    }
    phase.drop_objection(this, "avl_test");
  }
}

class random_test: random_test_parameterized!(32, 32)
{
  mixin uvm_component_utils;
  this(string name, uvm_component parent) {
    super(name, parent);
  }
}

void initializeESDL() {
  Vpi.initialize();

  auto test = new uvm_tb;
  test.multicore(0, 4);
  test.elaborate("test");
  test.set_seed(1);
  test.setVpiMode();

  test.start_bg();
}

alias funcType = void function();
shared extern(C) funcType[2] vlog_startup_routines = [&initializeESDL, null];

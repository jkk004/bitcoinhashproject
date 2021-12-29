module bitcoin_hash (input logic        clk, reset_n, start,
                     input logic [15:0] header_addr, hash_out_addr,
                    output logic        done, mem_clk, mem_we,
                    output logic [15:0] memory_addr,
                    output logic [31:0] memory_write_data,
                     input logic [31:0] memory_read_data);

parameter num_nonces = 16;
parameter integer NUM_OF_WORDS = 20; 

logic [31:0] hash_out[num_nonces];

// FSM state variables 
enum logic [2:0] {IDLE, BLOCK, COMPUTE, WRITE} state,next_state;

logic [2:0] phase, next_phase;

// Local variables
logic [31:0] w[64];
logic [31:0] message[16];
logic [31:0] S0,S1;
logic [31:0] hash[8];
logic [31:0] p1hash[8]; // phase 1 hash result
logic [31:0] A, B, C, D, E, F, G, H;
logic [ 7:0] i, t;
logic [15:0] offset; // in word address
logic [ 7:0] num_blocks;
logic [15:0] present_addr;
logic [31:0] present_write_data;
logic [ 7:0] tstep;

logic [15:0] words_read; // number of words read so far
logic [63:0] size_in_bits = NUM_OF_WORDS * 32;
logic [15:0] next_offset;
logic [ 7:0] next_i;
logic [15:0] next_words_read;
logic [31:0] next_message_i;
logic [31:0] next_hashout_nonce;
logic [7:0] nonce, next_nonce;

parameter int k[64] = '{
    32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
    32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
    32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
    32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
    32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
    32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
    32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
    32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};

// Student to add rest of the code here

// Generate request to memory
// for reading from memory to get original message
// for writing final computed has value
assign mem_clk = clk;
assign memory_addr = present_addr + next_offset;
assign memory_write_data = present_write_data;


assign num_blocks = determine_num_blocks(NUM_OF_WORDS); 
assign tstep = (i - 1);

// Note : Function defined are for reference purpose. Feel free to add more functions or modify below.
// Function to determine number of blocks in memory to fetch
function logic [15:0] determine_num_blocks(input logic [31:0] size);

  // Student to add function implementation
  
	// check if the message size + the 64 bits to record it is not a multiple of 512
	if ((size * 32 + 64) % 512) begin
		determine_num_blocks = (size * 32 + 64) / 512 + 1;
	end else begin
		// if it is a multiple of 512, then we can perfectly fit it in these number of blocks
		determine_num_blocks = (size * 32 + 64) / 512;
	end
 
endfunction


// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
    S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
    ch = (e & f) ^ ((~e) & g);
    t1 = h + S1 + ch + k[t] + w;
    S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;

    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
end
endfunction



// Right Rotation Example : right rotate input x by r
// Lets say input x = 1111 ffff 2222 3333 4444 6666 7777 8888
// lets say r = 4
// x >> r  will result in : 0000 1111 ffff 2222 3333 4444 6666 7777 
// x << (32-r) will result in : 8888 0000 0000 0000 0000 0000 0000 0000
// final right rotate expression is = (x >> r) | (x << (32-r));
// (0000 1111 ffff 2222 3333 4444 6666 7777) | (8888 0000 0000 0000 0000 0000 0000 0000)
// final value after right rotate = 8888 1111 ffff 2222 3333 4444 6666 7777
// Right rotation function

function logic [31:0] ror(input logic [31:0] in,
                                  input logic [7:0] s);
begin
   ror = (in >> s) | (in << (32-s));
end
endfunction


// gets value of w[t]
function logic [31:0] wt (input logic [7:0] t); 
begin
	if (t < 16) begin
		wt = w[t];
	end else begin
		wt = w[t-16] + (ror(w[t-15], 7) ^ ror(w[t-15], 18) ^ (w[t-15] >> 3)) + w[t-7] + (ror(w[t-2], 17) ^ ror(w[t-2], 19) ^ (w[t-2] >> 10));
	end
end
endfunction

always_ff @(posedge clk, negedge reset_n)
begin
  if (!reset_n) begin
    state <= IDLE;
  end 
  else begin 
	state <= next_state;
	offset <= next_offset;
	i <= next_i;
	words_read <= next_words_read;
	nonce <= next_nonce;
	phase <= next_phase;
	
	if (state == IDLE) begin
		hash[0] <= 32'h6a09e667;
		hash[1] <= 32'hbb67ae85;
		hash[2] <= 32'h3c6ef372;
		hash[3] <= 32'ha54ff53a;
		hash[4] <= 32'h510e527f;
		hash[5] <= 32'h9b05688c;
		hash[6] <= 32'h1f83d9ab;
		hash[7] <= 32'h5be0cd19;
	
	end
	
	// if reading we want to update message
	if (state == BLOCK) begin
		message[i] <= next_message_i;
	end else begin
		//otherwise preserve it
		message <= message;
	end
	
	if (state == COMPUTE) begin
	
		if (phase == 3) begin
			// update hash_out
			hash_out[nonce] <= next_hashout_nonce;
		end
	
		if (i == 0) begin
			// update hash values
			
			// store hash result of phase 1 for reuse
			if (phase == 1) begin
				hash[0] <= hash[0] + A;
				hash[1] <= hash[1] + B;
				hash[2] <= hash[2] + C;
				hash[3] <= hash[3] + D;
				hash[4] <= hash[4] + E;
				hash[5] <= hash[5] + F;
				hash[6] <= hash[6] + G;
				hash[7] <= hash[7] + H;
			
				p1hash[0] <= hash[0] + A;
				p1hash[1] <= hash[1] + B;
				p1hash[2] <= hash[2] + C;
				p1hash[3] <= hash[3] + D;
				p1hash[4] <= hash[4] + E;
				p1hash[5] <= hash[5] + F;
				p1hash[6] <= hash[6] + G;
				p1hash[7] <= hash[7] + H;
			end else if (phase == 3) begin
				// set hash back to constants in phase 3
				hash[0] <= 32'h6a09e667 + A;
				hash[1] <= 32'hbb67ae85 + B;
				hash[2] <= 32'h3c6ef372 + C;
				hash[3] <= 32'ha54ff53a + D;
				hash[4] <= 32'h510e527f + E;
				hash[5] <= 32'h9b05688c + F;
				hash[6] <= 32'h1f83d9ab + G;
				hash[7] <= 32'h5be0cd19 + H;
			end else if (phase == 2) begin
				// use p1 hash as starter value in p2
				hash[0] <= p1hash[0] + A;
				hash[1] <= p1hash[1] + B;
				hash[2] <= p1hash[2] + C;
				hash[3] <= p1hash[3] + D;
				hash[4] <= p1hash[4] + E;
				hash[5] <= p1hash[5] + F;
				hash[6] <= p1hash[6] + G;
				hash[7] <= p1hash[7] + H;
			end else begin
				hash[0] <= hash[0] + A;
				hash[1] <= hash[1] + B;
				hash[2] <= hash[2] + C;
				hash[3] <= hash[3] + D;
				hash[4] <= hash[4] + E;
				hash[5] <= hash[5] + F;
				hash[6] <= hash[6] + G;
				hash[7] <= hash[7] + H;
			end
		end
		
	end else begin
	//preserve value of hash out
		hash_out <= hash_out;
	end
	
  end
end



// SHA-256 FSM 
// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function
// and write back hash value back to memory
always_comb begin
	
	// set defaults to avoid inferred latches
	
	A = hash[0];
	B = hash[1];
	C = hash[2];
	D = hash[3];
	E = hash[4];
	F = hash[5];
	G = hash[6];
	H = hash[7];
	
	present_addr <= header_addr;
	present_write_data <= hash[0];
	
	next_words_read <= words_read;
	next_offset <= offset;
	next_i = i;
	next_message_i <= message[i];
	next_phase <= phase;
	next_nonce <= nonce;
	next_hashout_nonce <= 0;
	
	mem_we <= 0;
	t = 0;
	S0 = 0;
	S1 = 0;
	w = '{default: '0};
	
	
	

  if (!reset_n) begin
    next_state <= IDLE;
  end
  else begin 
	  case (state)
		// Initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
		IDLE: begin 
				
				mem_we <= 0;
				present_write_data <= 0;
				
				next_offset <= 0;
				next_i = 0;
				next_words_read <= 0;
				
				next_phase <= 1;
				next_nonce <= 0;
			
			// the only thing explicitly necessary in start block is to set the next state
			if(start) begin 
				next_state <= BLOCK;
		   end else begin
				next_state <= IDLE;
			end
		end

		// SHA-256 FSM 
		// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function    
		// and write back hash value back to memory
		BLOCK: begin
		// Fetch message in 512-bit block size
		// For each of 512-bit block initiate hash value computation
			
			// get up to 16 32-bit words from memory to form 512-bit message block
			if (i < 16 && phase != 3) begin
				// only read in from memory as long as there are words left to read
				if (words_read < NUM_OF_WORDS) begin
				
					if (i == 3 && phase == 2) begin
						next_message_i <= nonce;
					end else begin
						next_message_i <= memory_read_data;
					end
					
					// increment address 
					next_offset <= offset + 1; 
					next_words_read <= words_read + 1;
				end else begin
					//only reach this case in phase 2
					if (i == 4) begin
						//first padding word starts with 1
						next_message_i <= 32'h80000000;
					end else if (i < 15) begin
						// the rest of the padding is zero filled
						next_message_i <= 32'h0;
					end else begin
						next_message_i <= 32'd640;
					end
				
						
				end
				
				// continue reading message
				next_state <= BLOCK;
				//increment i
				next_i = i + 1;
					
			end else if (i < 16 && phase == 3) begin
				if (i < 8) begin
					next_message_i <= hash[i];
				end else if (i == 8) begin
					//first padding word starts with 1
					next_message_i <= 32'h80000000;
				end else if (i < 15)begin
					// the rest of the padding is zero filled
					next_message_i <= 32'h0;
				end else begin
				// last word for size
					next_message_i <= 32'd256;
				end
				
				
				// continue reading message
				next_state <= BLOCK;
				//increment i
				next_i = i + 1;
			end else begin
				// once we have the block, move to compute state
				next_state <= COMPUTE;
				// reset i for compute
				next_i = 0;
			end

		end
		
		// For each block compute hash function
		// Go back to BLOCK stage after each block hash computation is completed and if
		// there are still number of message blocks available in memory otherwise
		// move to WRITE stage
		COMPUTE: begin
		// 64 processing rounds steps for 512-bit block 
			
			A = hash[0];
			B = hash[1];
			C = hash[2];
			D = hash[3];
			E = hash[4];
			F = hash[5];
			G = hash[6];
			H = hash[7];
			//word expansion
			for (t = 0; t < 64; t++) begin
				if (t < 16) begin
					w[t] = message[t];
				end else begin
					S0 = ror(w[t-15], 7) ^ ror(w[t-15], 18) ^ (w[t-15] >> 3);
					S1 = ror(w[t-2], 17) ^ ror(w[t-2], 19) ^ (w[t-2] >> 10);
					w[t] = w[t-16] + S0 + w[t-7] + S1;
				end
			end
			// sha256
			for (t = 0; t < 64; t++) begin
				{A, B, C, D, E, F, G, H} = sha256_op(A, B, C, D, E, F, G, H, w[t], t);
			end
			
			if (words_read < NUM_OF_WORDS) begin
				// go back and read in another block
				next_state <= BLOCK;
				// reset i since we also use it as a counter in block
				next_i = 0;
				
				if (phase == 1) begin
					next_phase <= 2;
				end
				
			end else begin
			
				if (phase == 2) begin
					next_phase <= 3;
				end
				
				if (phase == 3) begin
					next_hashout_nonce <= hash[0];
					next_nonce <= nonce + 1;
					// we're going back to phase 2
					// set these variables so that BLOCK reads last 3 words again
					next_words_read <= 16;
					next_offset <= 16;
					next_phase <= 2;
				end
				
				// only go to write once we've computed all the hashes for each nonce
				if (nonce < 16) begin
					next_state <= BLOCK;
					next_i = 0;
				end else begin
					// if this was the last block, then go to write
					// switch memory address to address where we write the result
					present_addr <= hash_out_addr - 1;
					next_offset <= 0;
					next_state <= WRITE;
				end
			
			end
			
					
		end

		// h0 to h7 each are 32 bit hashes, which makes up total 256 bit value
		// h0 to h7 after compute stage has final computed hash value
		// write back these h0 to h7 to memory starting from hash_out_addr
		WRITE: begin
			present_addr <= hash_out_addr - 1;
			mem_we <= 1;
			if(offset < 17) begin
				present_write_data <= hash_out[offset];
				next_offset <= offset + 1;
				next_state <= WRITE;
			end
			else begin
				// once all 8 hash words have been written out, return to idle state
				next_state <= IDLE;
			end
			
		end
      endcase
	end
end

// Generate done when SHA256 hash computation has finished and moved to IDLE state
assign done = (state == IDLE);




endmodule

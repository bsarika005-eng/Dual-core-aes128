// ============================================================
// DUAL-CORE AES-128 ENCRYPTION
// SystemVerilog RTL
// ============================================================

module aes128_core (
    input  logic [127:0] plaintext,
    input  logic [127:0] key,
    output logic [127:0] ciphertext
);

    // --------------------------------------------------------
    // Galois Field Multiplication
    // --------------------------------------------------------

    function automatic [7:0] gmultiply;
        input [7:0] a;
        input [7:0] b;

        reg [7:0] aa;
        reg [7:0] bb;
        reg [7:0] p;
        integer i;

        begin
            aa = a;
            bb = b;
            p  = 8'h00;

            for (i = 0; i < 8; i = i + 1) begin

                if (bb[0])
                    p = p ^ aa;

                if (aa[7])
                    aa = (aa << 1) ^ 8'h1b;
                else
                    aa = aa << 1;

                bb = bb >> 1;

            end

            gmultiply = p;
        end

    endfunction


    // --------------------------------------------------------
    // Galois Field Power
    // Used to calculate multiplicative inverse
    // --------------------------------------------------------

    function automatic [7:0] gpow;
        input [7:0] a;

        reg [7:0] result;
        reg [7:0] base;
        integer i;

        begin

            result = 8'h01;
            base   = a;

            // a^254
            for (i = 0; i < 254; i = i + 1)
                result = gmultiply(result, base);

            if (a == 0)
                gpow = 0;
            else
                gpow = result;

        end

    endfunction


    // --------------------------------------------------------
    // AES S-Box
    // --------------------------------------------------------

    function automatic [7:0] sbox;
        input [7:0] x;

        reg [7:0] y;
        reg [7:0] r1;
        reg [7:0] r2;
        reg [7:0] r3;
        reg [7:0] r4;

        begin

            y = gpow(x);

            // Rotate left operations
            r1 = {y[6:0],y[7]};
            r2 = {y[5:0],y[7:6]};
            r3 = {y[4:0],y[7:5]};
            r4 = {y[3:0],y[7:4]};

            y = y ^ r1 ^ r2 ^ r3 ^ r4 ^ 8'h63;

            sbox = y;

        end

    endfunction


    // --------------------------------------------------------
    // RCON
    // --------------------------------------------------------

    function automatic [7:0] rcon;
        input integer n;

        reg [7:0] r;
        integer i;

        begin

            r = 8'h01;

            for (i = 1; i < n; i = i + 1) begin

                if (r[7])
                    r = (r << 1) ^ 8'h1b;
                else
                    r = r << 1;

            end

            rcon = r;

        end

    endfunction


    // --------------------------------------------------------
    // Internal variables
    // --------------------------------------------------------

    reg [31:0] w [0:43];

    reg [7:0] state [0:15];

    reg [7:0] temp_state [0:15];

    reg [7:0] mix_state [0:15];

    reg [7:0] round_key [0:15];

    reg [31:0] temp_word;

    reg [31:0] temp_rot;

    reg [31:0] temp_sub;

    integer i;
    integer j;
    integer round;


    // --------------------------------------------------------
    // AES Encryption
    // --------------------------------------------------------

    always @* begin

        // ====================================================
        // STEP 1: KEY EXPANSION
        // ====================================================

        // Original 128-bit key -> four 32-bit words

        w[0] = key[127:96];
        w[1] = key[95:64];
        w[2] = key[63:32];
        w[3] = key[31:0];


        // Generate remaining 40 words

        for (i = 4; i < 44; i = i + 1) begin

            temp_word = w[i-1];

            if ((i % 4) == 0) begin

                // RotWord
                temp_rot = {
                    temp_word[23:0],
                    temp_word[31:24]
                };

                // SubWord
                temp_sub = {
                    sbox(temp_rot[31:24]),
                    sbox(temp_rot[23:16]),
                    sbox(temp_rot[15:8]),
                    sbox(temp_rot[7:0])
                };

                // XOR RCON
                temp_word =
                    temp_sub ^
                    {rcon(i/4),24'h000000};

            end

            w[i] = w[i-4] ^ temp_word;

        end


        // ====================================================
        // STEP 2: LOAD PLAINTEXT
        // ====================================================

        for (i = 0; i < 16; i = i + 1)

            state[i] =
                plaintext[127 - (i*8) -: 8];


        // ====================================================
        // STEP 3: INITIAL ADD ROUND KEY
        // ====================================================

        for (i = 0; i < 16; i = i + 1)

            round_key[i] =
                key[127 - (i*8) -: 8];

        for (i = 0; i < 16; i = i + 1)

            state[i] =
                state[i] ^ round_key[i];


        // ====================================================
        // STEP 4: AES ROUNDS 1 TO 9
        // ====================================================

        for (round = 1; round <= 9; round = round + 1) begin

            // ------------------------------------------------
            // SubBytes
            // ------------------------------------------------

            for (i = 0; i < 16; i = i + 1)

                temp_state[i] =
                    sbox(state[i]);


            // ------------------------------------------------
            // ShiftRows
            // ------------------------------------------------

            state[0]  = temp_state[0];
            state[1]  = temp_state[5];
            state[2]  = temp_state[10];
            state[3]  = temp_state[15];

            state[4]  = temp_state[4];
            state[5]  = temp_state[9];
            state[6]  = temp_state[14];
            state[7]  = temp_state[3];

            state[8]  = temp_state[8];
            state[9]  = temp_state[13];
            state[10] = temp_state[2];
            state[11] = temp_state[7];

            state[12] = temp_state[12];
            state[13] = temp_state[1];
            state[14] = temp_state[6];
            state[15] = temp_state[11];


            // ------------------------------------------------
            // MixColumns
            // ------------------------------------------------

            for (j = 0; j < 4; j = j + 1) begin

                mix_state[4*j] =
                    gmultiply(state[4*j],8'h02) ^
                    gmultiply(state[4*j+1],8'h03) ^
                    state[4*j+2] ^
                    state[4*j+3];

                mix_state[4*j+1] =
                    state[4*j] ^
                    gmultiply(state[4*j+1],8'h02) ^
                    gmultiply(state[4*j+2],8'h03) ^
                    state[4*j+3];

                mix_state[4*j+2] =
                    state[4*j] ^
                    state[4*j+1] ^
                    gmultiply(state[4*j+2],8'h02) ^
                    gmultiply(state[4*j+3],8'h03);

                mix_state[4*j+3] =
                    gmultiply(state[4*j],8'h03) ^
                    state[4*j+1] ^
                    state[4*j+2] ^
                    gmultiply(state[4*j+3],8'h02);

            end


            // Copy MixColumns result

            for (i = 0; i < 16; i = i + 1)

                state[i] = mix_state[i];


            // ------------------------------------------------
            // AddRoundKey
            // ------------------------------------------------

            for (i = 0; i < 16; i = i + 1) begin

                case (i)

                    0:
                        state[i] =
                            state[i] ^ w[round*4][31:24];

                    1:
                        state[i] =
                            state[i] ^ w[round*4][23:16];

                    2:
                        state[i] =
                            state[i] ^ w[round*4][15:8];

                    3:
                        state[i] =
                            state[i] ^ w[round*4][7:0];

                    4:
                        state[i] =
                            state[i] ^ w[round*4+1][31:24];

                    5:
                        state[i] =
                            state[i] ^ w[round*4+1][23:16];

                    6:
                        state[i] =
                            state[i] ^ w[round*4+1][15:8];

                    7:
                        state[i] =
                            state[i] ^ w[round*4+1][7:0];

                    8:
                        state[i] =
                            state[i] ^ w[round*4+2][31:24];

                    9:
                        state[i] =
                            state[i] ^ w[round*4+2][23:16];

                    10:
                        state[i] =
                            state[i] ^ w[round*4+2][15:8];

                    11:
                        state[i] =
                            state[i] ^ w[round*4+2][7:0];

                    12:
                        state[i] =
                            state[i] ^ w[round*4+3][31:24];

                    13:
                        state[i] =
                            state[i] ^ w[round*4+3][23:16];

                    14:
                        state[i] =
                            state[i] ^ w[round*4+3][15:8];

                    15:
                        state[i] =
                            state[i] ^ w[round*4+3][7:0];

                endcase

            end

        end


        // ====================================================
        // STEP 5: FINAL ROUND
        // No MixColumns
        // ====================================================

        // SubBytes

        for (i = 0; i < 16; i = i + 1)

            temp_state[i] =
                sbox(state[i]);


        // ShiftRows

        state[0]  = temp_state[0];
        state[1]  = temp_state[5];
        state[2]  = temp_state[10];
        state[3]  = temp_state[15];

        state[4]  = temp_state[4];
        state[5]  = temp_state[9];
        state[6]  = temp_state[14];
        state[7]  = temp_state[3];

        state[8]  = temp_state[8];
        state[9]  = temp_state[13];
        state[10] = temp_state[2];
        state[11] = temp_state[7];

        state[12] = temp_state[12];
        state[13] = temp_state[1];
        state[14] = temp_state[6];
        state[15] = temp_state[11];


        // Final AddRoundKey

        for (i = 0; i < 16; i = i + 1) begin

            case (i)

                0:
                    state[i] =
                        state[i] ^ w[40][31:24];

                1:
                    state[i] =
                        state[i] ^ w[40][23:16];

                2:
                    state[i] =
                        state[i] ^ w[40][15:8];

                3:
                    state[i] =
                        state[i] ^ w[40][7:0];

                4:
                    state[i] =
                        state[i] ^ w[41][31:24];

                5:
                    state[i] =
                        state[i] ^ w[41][23:16];

                6:
                    state[i] =
                        state[i] ^ w[41][15:8];

                7:
                    state[i] =
                        state[i] ^ w[41][7:0];

                8:
                    state[i] =
                        state[i] ^ w[42][31:24];

                9:
                    state[i] =
                        state[i] ^ w[42][23:16];

                10:
                    state[i] =
                        state[i] ^ w[42][15:8];

                11:
                    state[i] =
                        state[i] ^ w[42][7:0];

                12:
                    state[i] =
                        state[i] ^ w[43][31:24];

                13:
                    state[i] =
                        state[i] ^ w[43][23:16];

                14:
                    state[i] =
                        state[i] ^ w[43][15:8];

                15:
                    state[i] =
                        state[i] ^ w[43][7:0];

            endcase

        end


        // ====================================================
        // STEP 6: OUTPUT CIPHERTEXT
        // ====================================================

        ciphertext = 128'b0;

        for (i = 0; i < 16; i = i + 1)

            ciphertext[127 - (i*8) -: 8] =
                state[i];

    end

endmodule



// ============================================================
// DUAL-CORE AES TOP MODULE
// ============================================================

module dual_core_aes (

    input logic [127:0] plaintext0,
    input logic [127:0] plaintext1,

    input logic [127:0] key,

    output logic [127:0] ciphertext0,
    output logic [127:0] ciphertext1

);

    // --------------------------------------------------------
    // AES CORE 0
    // --------------------------------------------------------

    aes128_core core0 (

        .plaintext(plaintext0),
        .key(key),
        .ciphertext(ciphertext0)

    );


    // --------------------------------------------------------
    // AES CORE 1
    // --------------------------------------------------------

    aes128_core core1 (

        .plaintext(plaintext1),
        .key(key),
        .ciphertext(ciphertext1)

    );

endmodule

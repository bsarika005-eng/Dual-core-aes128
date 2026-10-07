// Code your testbench here
// or browse Examples
module tb;

    logic [127:0] plaintext0;
    logic [127:0] plaintext1;

    logic [127:0] key;

    logic [127:0] ciphertext0;
    logic [127:0] ciphertext1;


    // ========================================================
    // DUT
    // ========================================================

    dual_core_aes dut (

        .plaintext0(plaintext0),
        .plaintext1(plaintext1),

        .key(key),

        .ciphertext0(ciphertext0),
        .ciphertext1(ciphertext1)

    );


    // ========================================================
    // TEST
    // ========================================================

    initial begin

        // Enable waveform
        $dumpfile("dump.vcd");
        $dumpvars(0,tb);


        // ----------------------------------------------------
        // Standard AES-128 key
        // ----------------------------------------------------

        key =
            128'h000102030405060708090a0b0c0d0e0f;


        // ----------------------------------------------------
        // Core 0 plaintext
        // ----------------------------------------------------

        plaintext0 =
            128'h00112233445566778899aabbccddeeff;


        // ----------------------------------------------------
        // Core 1 plaintext
        // ----------------------------------------------------

        plaintext1 =
            128'h112233445566778899aabbccddeeff00;


        #100;


        // ====================================================
        // DISPLAY RESULTS
        // ====================================================

        $display("");
        $display("==============================================");
        $display("       DUAL-CORE AES-128 ENCRYPTION");
        $display("==============================================");

        $display("");

        $display("KEY:");
        $display("%h",key);

        $display("");

        $display("CORE 0");
        $display("----------------------------------------------");

        $display("Plaintext  : %h",plaintext0);

        $display("Ciphertext : %h",ciphertext0);

        $display("");

        $display("CORE 1");
        $display("----------------------------------------------");

        $display("Plaintext  : %h",plaintext1);

        $display("Ciphertext : %h",ciphertext1);

        $display("");


        // ====================================================
        // VERIFY CORE 0
        // ====================================================

        if (ciphertext0 ==
            128'h69c4e0d86a7b0430d8cdb78070b4c55a) begin

            $display("CORE 0 AES TEST : PASS");

        end
        else begin

            $display("CORE 0 AES TEST : FAIL");

        end


        // ====================================================
        // FINISH
        // ====================================================

        $display("");
        $display("==============================================");
        $display("       SIMULATION COMPLETE");
        $display("==============================================");

        #10;

        $finish;

    end

endmodule

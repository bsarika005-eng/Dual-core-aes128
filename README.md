# Dual-core-aes128
# Dual-Core AES-128 Encryption

A SystemVerilog RTL implementation of AES-128 with two parallel encryption
cores that share one 128-bit key. Each core encrypts its own 128-bit
plaintext block independently, so two blocks are processed at the same time.

## Features
- Full AES-128 encryption with 10 rounds: key expansion, SubBytes,
  ShiftRows, MixColumns and AddRoundKey
- S-box computed using the GF(2^8) multiplicative inverse and the affine
  transform, with no lookup table
- Two identical `aes128_core` instances inside the `dual_core_aes` top module
- Testbench with console output and waveform dump (`dump.vcd`)

## Project Structure
dual-core-aes128/
├── rtl/
│ └── dual_core_aes.sv # aes128_core and dual_core_aes modules
├── tb/
│ └── tb.sv # Testbench
├── docs/
│ └── waveform.png # EPWave simulation screenshot
└── README.md

## Block Diagram

plaintext0 ──► [ AES Core 0 ] ──► ciphertext0
▲
key ────────────────┤
▼
plaintext1 ──► [ AES Core 1 ] ──► ciphertext1


## How to Run

**EDA Playground:** paste the design into the design pane and the testbench
into the testbench pane, select a SystemVerilog simulator, and click Run.

**Icarus Verilog:**
```bash
iverilog -g2012 rtl/dual_core_aes.sv tb/tb.sv
vvp a.out
```

## Verification
Core 0 is checked against the FIPS-197 Appendix C.1 test vector:

| Item       | Value                              |
|------------|------------------------------------|
| Key        | 000102030405060708090a0b0c0d0e0f   |
| Plaintext  | 00112233445566778899aabbccddeeff   |
| Ciphertext | 69c4e0d86a7b0430d8cdb78070b4c55a   |

The simulated output matches the expected ciphertext (PASS).

## Simulation Result
![Waveform](docs/waveform.png)

## Limitations
- The design is purely combinational and intended for simulation.
- For synthesis, replace the S-box function with a lookup table and add
  clocked pipeline registers.

## Future Work
- Add clock, reset and start/done handshake
- Pipelined architecture for higher throughput
- AES decryption and support for other key sizes

## License
MIT License

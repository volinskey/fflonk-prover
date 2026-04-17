pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/poseidon.circom";

// Medium-size test circuit: chained Poseidon(1) hashes.
//
// Each Poseidon(1) call compiled via circomlib is ~213 R1CS constraints.
// N=154 iterations → roughly 2^15 ≈ 32k constraints, large enough to
// exercise FFT/NTT scaling without the minutes-long compile times of
// really large circuits.
//
// Public signal: final hash. Private signal: initial preimage.
// Knowledge of the preimage → knowledge of a valid witness.

template PoseidonChain(N) {
    signal input preimage;
    signal output hash;

    component poseidons[N];
    signal intermediates[N + 1];

    intermediates[0] <== preimage;

    for (var i = 0; i < N; i++) {
        poseidons[i] = Poseidon(1);
        poseidons[i].inputs[0] <== intermediates[i];
        intermediates[i + 1] <== poseidons[i].out;
    }

    hash <== intermediates[N];
}

component main = PoseidonChain(154);

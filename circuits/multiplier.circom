pragma circom 2.1.0;

// Minimal smoke-test circuit: prove knowledge of (a, b) such that a * b = c.
// Public signal: c. Private signals: a, b.
//
// Used as the smallest-possible FFLONK correctness fixture. Only a handful
// of constraints — fast to compile, fast to prove, exercises the full
// setup/prove/verify pipeline end-to-end.

template Multiplier() {
    signal input a;
    signal input b;
    signal output c;

    c <== a * b;
}

component main = Multiplier();

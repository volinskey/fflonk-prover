fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("fflonk-prover {}", fflonk_prover::VERSION);
        return;
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return;
    }
    print_help();
}

fn print_help() {
    println!("fflonk-prover {}", fflonk_prover::VERSION);
    println!();
    println!("USAGE:");
    println!("    fflonk-prover <SUBCOMMAND> [ARGS]");
    println!();
    println!("SUBCOMMANDS:");
    println!("    prove    Generate a FFLONK proof (not yet implemented)");
    println!("    verify   Verify a FFLONK proof locally (not yet implemented)");
    println!("    info     Display proving key metadata (not yet implemented)");
    println!();
    println!("FLAGS:");
    println!("    -V, --version    Print version");
    println!("    -h, --help       Print help");
}

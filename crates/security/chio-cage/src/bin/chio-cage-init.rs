fn main() {
    if chio_cage::run_cage_init().is_err() {
        std::process::exit(127);
    }
}

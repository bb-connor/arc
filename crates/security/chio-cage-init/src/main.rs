fn main() {
    #[cfg(target_os = "linux")]
    if chio_cage_init::run_cage_init().is_ok() {
        return;
    }
    std::process::exit(127);
}

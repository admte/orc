fn main() {
    // Before any argument parsing: invoked under the reboot shim's name, this binary is
    // the shim, and its arguments are the platform's (`/r`, `/t 0`), not the CLI's.
    if let Some(code) = orc_app::reboot::maybe_run_shim() {
        std::process::exit(code);
    }
    std::process::exit(orc_cli::main_entry());
}

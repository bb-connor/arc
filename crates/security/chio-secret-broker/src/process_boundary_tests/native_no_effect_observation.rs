//! Observe every provider connection until the verified owner completion barrier.
use super::super::observation_owner::{adopt_inherited_observation, DONE};
use super::*;
use rustix::event::{poll, PollFd, PollFlags};

pub(super) fn observe_until_owned_done(listener: &TcpListener) -> io::Result<()> {
    // SAFETY: native ObservationOwner::spawn exclusively transfers the endpoint
    // to this helper; no other value in the executable owns its inherited slot.
    #[allow(unsafe_code)]
    let mut owner = unsafe { adopt_inherited_observation() }?;
    let complete = PathBuf::from(required_environment(FALLBACK_MARKER_ENV));
    loop {
        let owner_ready = {
            let mut descriptors = [
                PollFd::new(listener, PollFlags::IN),
                PollFd::new(&owner, PollFlags::IN),
            ];
            match poll(&mut descriptors, None) {
                Err(rustix::io::Errno::INTR) => continue,
                result => {
                    result?;
                }
            }
            descriptors[1]
                .revents()
                .intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL)
        };
        // An observed connection always fails, even if completion is ready in
        // the same poll. Completion cannot hide an effect before broker death.
        require_no_connection(listener);
        if owner_ready {
            let mut message = [0_u8];
            match owner.read(&mut message)? {
                0 => {
                    eprintln!("zero-effect observation owner cancelled");
                    return Err(io::Error::other("zero-effect observation owner cancelled"));
                }
                1 if message[0] == DONE => {
                    if fs::read(&complete)? != b"complete" {
                        return Err(io::Error::other(
                            "zero-effect completion barrier is invalid",
                        ));
                    }
                    break;
                }
                _ => return Err(io::Error::other("zero-effect owner message is invalid")),
            }
        }
    }
    let quiet_deadline = Instant::now() + Duration::from_millis(250);
    while Instant::now() < quiet_deadline {
        require_no_connection(listener);
        thread::sleep(Duration::from_millis(2));
    }
    require_no_connection(listener);
    println!("{ZERO_EFFECT_REPORT}");
    Ok(())
}

fn require_no_connection(listener: &TcpListener) {
    match listener.accept() {
        Ok(_) => {
            eprintln!("broker death before send still reached the provider");
            panic!("broker death before send still reached the provider");
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Err(error) => panic!("zero-effect provider observation failed: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::observation_owner::ObservationOwner;
    use super::*;
    use std::net::{SocketAddr, TcpStream};

    type Setup = (
        tempfile::TempDir,
        PathBuf,
        CanaryProbe,
        ObservationOwner,
        ManagedChild,
        SocketAddr,
    );

    fn setup() -> std::result::Result<Setup, Box<dyn std::error::Error>> {
        let directory = crate::private_tempdir()?;
        let root = fs::canonicalize(directory.path())?;
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec![UPSTREAM_HOST.into()])?;
        let certificate = root.join("observer.der");
        let key = root.join("observer-key.der");
        write_private(&certificate, cert.der().as_ref());
        write_private(&key, &key_pair.serialize_der());
        let canary = random_canary();
        let probe = CanaryProbe::from_bytes(&canary);
        let marker = root.join("complete");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let address = listener.local_addr()?;
        let mut command = helper_command(UPSTREAM_HELPER, "upstream", &root);
        command
            .env(CERT_ENV, certificate)
            .env(KEY_ENV, key)
            .env(FALLBACK_MARKER_ENV, &marker)
            .env(CANARY_LENGTH_ENV, probe.length.to_string())
            .env(CANARY_DIGEST_ENV, hex::encode(probe.sha256))
            .env(NO_EFFECT_ENV, "1");
        let (owner, child) = ObservationOwner::spawn(command, listener)?;
        Ok((directory, marker, probe, owner, child, address))
    }

    #[test]
    fn owned_zero_effect_cancellation_never_emits_success_and_reaps_child() -> TestResult {
        let (_directory, _marker, probe, owner, mut child, _address) = setup()?;
        assert!(child.try_wait().is_none());
        drop(owner);
        let output = child.wait_output();
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stdout).contains(ZERO_EFFECT_REPORT));
        assert!(String::from_utf8_lossy(&output.stderr)
            .contains("zero-effect observation owner cancelled"));
        probe.assert_absent(&output.stdout, "cancelled observation stdout");
        probe.assert_absent(&output.stderr, "cancelled observation stderr");
        Ok(())
    }

    #[test]
    fn owned_zero_effect_completion_cannot_hide_a_real_queued_connection() -> TestResult {
        let (_directory, marker, probe, owner, mut child, address) = setup()?;
        let _connection = TcpStream::connect_timeout(&address, Duration::from_secs(1))?;
        write_private(&marker, b"complete");
        // The child may already have refused the connection and closed its
        // channel. Either send outcome leaves the real observation failing.
        let _completion = owner.complete_after_verified_reap();
        let output = child.wait_output();
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stdout).contains(ZERO_EFFECT_REPORT));
        assert!(String::from_utf8_lossy(&output.stderr)
            .contains("broker death before send still reached the provider"));
        probe.assert_absent(&output.stdout, "refused observation stdout");
        probe.assert_absent(&output.stderr, "refused observation stderr");
        Ok(())
    }

    #[test]
    fn owned_zero_effect_valid_done_retains_the_independent_quiet_scan() -> TestResult {
        let (_directory, marker, probe, owner, mut child, _address) = setup()?;
        write_private(&marker, b"complete");
        owner.complete_after_verified_reap()?;
        let output = child.wait_output();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains(ZERO_EFFECT_REPORT));
        probe.assert_absent(&output.stdout, "completed observation stdout");
        probe.assert_absent(&output.stderr, "completed observation stderr");
        Ok(())
    }
}

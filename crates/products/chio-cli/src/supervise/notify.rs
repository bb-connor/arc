//! The systemd notify protocol, as much of it as readiness and stop status need.
//!
//! systemd passes the notify socket in `NOTIFY_SOCKET`; a `Type=notify`
//! unit is not active until its main process sends `READY=1`. Every send is
//! best effort: a supervisor whose manager has gone away must still stop its
//! service cleanly.

use std::ffi::OsStr;
use std::io;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;

enum Target {
    Path(PathBuf),
    #[cfg(target_os = "linux")]
    Abstract(Vec<u8>),
}

/// Sends notify messages to the manager, or nowhere when none is listening.
pub struct Notifier {
    target: Option<Target>,
}

impl Notifier {
    /// The notifier for the socket in `NOTIFY_SOCKET`, disabled when unset.
    pub fn from_environment() -> Self {
        match std::env::var_os("NOTIFY_SOCKET") {
            Some(socket) if !socket.is_empty() => Self::for_socket(&socket),
            _ => Self::disabled(),
        }
    }

    /// The notifier for one socket address as systemd spells it: a path, or
    /// on Linux an abstract name introduced by `@`.
    pub fn for_socket(socket: &OsStr) -> Self {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::ffi::OsStrExt;
            if let Some(name) = socket.as_bytes().strip_prefix(b"@") {
                return Self {
                    target: Some(Target::Abstract(name.to_vec())),
                };
            }
        }
        Self {
            target: Some(Target::Path(PathBuf::from(socket))),
        }
    }

    pub fn disabled() -> Self {
        Self { target: None }
    }

    /// Report that the service answers.
    pub fn ready(&self) -> io::Result<()> {
        self.send("READY=1")
    }

    /// Report that the service is draining.
    pub fn stopping(&self) -> io::Result<()> {
        self.send("STOPPING=1")
    }

    /// Report a one-line status for `systemctl status`.
    pub fn status(&self, text: &str) -> io::Result<()> {
        let line: String = text.chars().filter(|c| !c.is_control()).collect();
        self.send(&format!("STATUS={line}"))
    }

    fn send(&self, message: &str) -> io::Result<()> {
        let Some(target) = &self.target else {
            return Ok(());
        };
        let socket = UnixDatagram::unbound()?;
        match target {
            Target::Path(path) => socket.send_to(message.as_bytes(), path).map(|_| ()),
            #[cfg(target_os = "linux")]
            Target::Abstract(name) => {
                use std::os::linux::net::SocketAddrExt;
                let address = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
                socket.send_to_addr(message.as_bytes(), &address).map(|_| ())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receive(socket: &UnixDatagram) -> String {
        let mut buffer = [0_u8; 256];
        let length = socket
            .recv(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        String::from_utf8_lossy(&buffer[..length]).into_owned()
    }

    #[test]
    fn messages_reach_a_path_socket_and_status_stays_on_one_line() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = directory.path().join("notify.sock");
        let manager = UnixDatagram::bind(&path).unwrap_or_else(|error| panic!("{error}"));
        let notifier = Notifier::for_socket(path.as_os_str());
        notifier.ready().unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(receive(&manager), "READY=1");
        notifier
            .status("ready\nMAINPID=1")
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(receive(&manager), "STATUS=readyMAINPID=1");
        notifier.stopping().unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(receive(&manager), "STOPPING=1");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn messages_reach_an_abstract_socket() {
        use std::os::linux::net::SocketAddrExt;
        let name = format!("chio-supervise-test-{}", std::process::id());
        let address = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
        let manager = UnixDatagram::bind_addr(&address).unwrap_or_else(|error| panic!("{error}"));
        let notifier = Notifier::for_socket(OsStr::new(&format!("@{name}")));
        notifier.ready().unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(receive(&manager), "READY=1");
    }

    #[test]
    fn a_disabled_notifier_accepts_every_message() {
        let notifier = Notifier::disabled();
        assert!(notifier.ready().is_ok());
        assert!(notifier.status("anything").is_ok());
    }
}

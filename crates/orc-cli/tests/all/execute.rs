//! Shipped CLI against the public execution protocol: flags and argument
//! boundaries, stdin EOF, binary stream separation, and process exit status.
use orc_access::{
    access_service_server::{AccessService, AccessServiceServer},
    *,
};
use std::{pin::Pin, process::Stdio};
use tokio::sync::mpsc;
use tokio_stream::{
    Stream, StreamExt,
    wrappers::{ReceiverStream, TcpListenerStream},
};
use tonic::{Request, Response, Status, Streaming};

type Frames<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;
struct Service;
#[tonic::async_trait]
impl AccessService for Service {
    type OpenSessionStream = Frames<SessionEvent>;
    type ForwardStream = Frames<ForwardFrame>;
    type ExecuteStream = Frames<ExecuteFrame>;
    async fn describe(
        &self,
        _: Request<DescribeRequest>,
    ) -> Result<Response<DescribeResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn authorize_target(
        &self,
        _: Request<AuthorizeTargetRequest>,
    ) -> Result<Response<ResolvedTarget>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn forward(
        &self,
        _: Request<Streaming<ForwardFrame>>,
    ) -> Result<Response<Self::ForwardStream>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn open_session(
        &self,
        request: Request<OpenSessionRequest>,
    ) -> Result<Response<Self::OpenSessionStream>, Status> {
        assert_eq!(
            request.metadata().get("authorization").unwrap(),
            "Bearer test-key"
        );
        assert_eq!(request.get_ref().org, "test-org");
        assert!(request.get_ref().break_glass);
        let event = SessionEvent {
            kind: Some(session_event::Kind::Opened(SessionOpened {
                session_id: "test-session".into(),
                ..Default::default()
            })),
        };
        Ok(Response::new(Box::pin(
            tokio_stream::once(Ok(event)).chain(tokio_stream::pending()),
        )))
    }
    async fn execute(
        &self,
        request: Request<Streaming<ExecuteFrame>>,
    ) -> Result<Response<Self::ExecuteStream>, Status> {
        use execute_frame::Kind;
        assert_eq!(
            request.metadata().get("authorization").unwrap(),
            "Bearer test-key"
        );
        let mut input = request.into_inner();
        let Some(ExecuteFrame {
            kind: Some(Kind::Open(open)),
        }) = input.message().await?
        else {
            panic!("open frame")
        };
        assert_eq!(open.node, "n_d000000000001");
        assert_eq!(open.session_id, "test-session");
        if open.tty {
            assert!(open.command.is_empty());
            assert!(open.stdin);
            let stream = tokio_stream::iter([
                Ok(ExecuteFrame {
                    kind: Some(Kind::Ready(true)),
                }),
                Ok(ExecuteFrame {
                    kind: Some(Kind::Exit(ExecuteExit {
                        code: 23,
                        signal: String::new(),
                    })),
                }),
            ]);
            return Ok(Response::new(Box::pin(stream)));
        }
        assert_eq!(open.command, ["program", "a b", "$HOME;echo", "--flag", ""]);
        assert!(!open.tty);
        assert!(open.stdin);
        let (tx, rx) = mpsc::channel(2);
        tokio::spawn(async move {
            tx.send(Ok(ExecuteFrame {
                kind: Some(Kind::Ready(true)),
            }))
            .await
            .unwrap();
            let mut bytes = Vec::new();
            loop {
                match input.message().await.unwrap().expect("stdin EOF").kind {
                    Some(Kind::Stdin(data)) => bytes.extend_from_slice(&data),
                    Some(Kind::StdinEof(true)) => break,
                    _ => panic!("unexpected input"),
                }
            }
            assert_eq!(bytes, b"input\0binary\n");
            for kind in [
                Kind::Stdout(b"out\0\xff\n".to_vec().into()),
                Kind::Stderr(b"err\n".to_vec().into()),
                Kind::Exit(ExecuteExit {
                    code: 42,
                    signal: String::new(),
                }),
            ] {
                tx.send(Ok(ExecuteFrame { kind: Some(kind) }))
                    .await
                    .unwrap();
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

#[tokio::test]
async fn exec_preserves_argv_binary_streams_eof_and_remote_status() {
    use tokio::io::AsyncWriteExt;
    let (address, dir, server) = fixture().await;
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "exec",
            "-i",
            "--server",
            &format!("http://{address}"),
            "n_d000000000001",
            "--",
            "program",
            "a b",
            "$HOME;echo",
            "--flag",
            "",
        ])
        .env("ORC_CONFIG_DIR", dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"input\0binary\n")
        .await
        .unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(10), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(42),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, b"out\0\xff\n");
    assert_eq!(result.stderr, b"err\n");
    server.abort();
}

async fn fixture() -> (
    std::net::SocketAddr,
    tempfile::TempDir,
    tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(AccessServiceServer::new(Service))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("config.json"), serde_json::to_vec(&serde_json::json!({
        "default_org": "test-org", "credentials": { address.to_string(): { "username": "test", "token": "test-key" } }
    })).unwrap()).unwrap();
    (address, dir, server)
}

#[cfg(unix)]
#[tokio::test]
async fn sh_restores_the_local_terminal_after_remote_exit() {
    use std::os::fd::{AsRawFd, FromRawFd};
    let (address, dir, server) = fixture().await;
    // SAFETY: openpty initializes two owned descriptors and tcgetattr writes
    // valid termios storage. Files close each descriptor exactly once.
    #[allow(unsafe_code)]
    let (master, slave, original) = unsafe {
        let (mut master, mut slave) = (-1, -1);
        assert_eq!(
            libc::openpty(
                &raw mut master,
                &raw mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null()
            ),
            0
        );
        let mut original = std::mem::zeroed::<libc::termios>();
        assert_eq!(libc::tcgetattr(slave, &raw mut original), 0);
        (
            std::fs::File::from_raw_fd(master),
            std::fs::File::from_raw_fd(slave),
            original,
        )
    };
    let child = tokio::process::Command::new(env!("CARGO_BIN_EXE_orc"))
        .args([
            "sh",
            "--server",
            &format!("http://{address}"),
            "n_d000000000001",
        ])
        .env("ORC_CONFIG_DIR", dir.path())
        .stdin(slave.try_clone().unwrap())
        .stdout(slave.try_clone().unwrap())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(10), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(23),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    #[allow(unsafe_code)]
    let restored = unsafe {
        let mut restored = std::mem::zeroed::<libc::termios>();
        assert_eq!(libc::tcgetattr(slave.as_raw_fd(), &raw mut restored), 0);
        restored
    };
    assert_eq!(restored.c_lflag, original.c_lflag);
    assert_eq!(restored.c_iflag, original.c_iflag);
    assert_eq!(restored.c_oflag, original.c_oflag);
    assert_eq!(restored.c_cc, original.c_cc);
    drop(master);
    server.abort();
}

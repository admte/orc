use prost::Message as _;

use orc_access::{DescribeResponse, ForwardFrame, OpenSessionRequest, forward_frame};

#[test]
fn public_field_numbers_remain_stable() {
    let description = DescribeResponse {
        max_targets_per_session: 7,
        ..DescribeResponse::default()
    };
    assert_eq!(description.encode_to_vec(), [0x50, 0x07]);

    let session = OpenSessionRequest {
        break_glass: true,
        ..OpenSessionRequest::default()
    };
    assert_eq!(session.encode_to_vec(), [0x18, 0x01]);

    let frame = ForwardFrame {
        kind: Some(forward_frame::Kind::Data(bytes::Bytes::from_static(b"orc"))),
    };
    assert_eq!(frame.encode_to_vec(), [0x1a, 0x03, b'o', b'r', b'c']);
}

#[test]
fn generated_client_and_server_interfaces_are_public() {
    fn accepts_client<T>(_client: orc_access::access_service_client::AccessServiceClient<T>) {}
    fn accepts_server<T>(_server: orc_access::access_service_server::AccessServiceServer<T>) {}

    let _ = accepts_client::<tonic::transport::Channel>;
    let _ = accepts_server::<DummyAccessService>;
    assert_eq!(
        orc_access::access_service_server::SERVICE_NAME,
        "orc.access.v1.AccessService"
    );
}

struct DummyAccessService;

#[async_trait::async_trait]
impl orc_access::access_service_server::AccessService for DummyAccessService {
    type OpenSessionStream = tokio_stream::Empty<Result<orc_access::SessionEvent, tonic::Status>>;
    type ForwardStream = tokio_stream::Empty<Result<orc_access::ForwardFrame, tonic::Status>>;

    async fn describe(
        &self,
        _request: tonic::Request<orc_access::DescribeRequest>,
    ) -> Result<tonic::Response<orc_access::DescribeResponse>, tonic::Status> {
        unimplemented!()
    }

    async fn open_session(
        &self,
        _request: tonic::Request<orc_access::OpenSessionRequest>,
    ) -> Result<tonic::Response<Self::OpenSessionStream>, tonic::Status> {
        unimplemented!()
    }

    async fn authorize_target(
        &self,
        _request: tonic::Request<orc_access::AuthorizeTargetRequest>,
    ) -> Result<tonic::Response<orc_access::ResolvedTarget>, tonic::Status> {
        unimplemented!()
    }

    async fn forward(
        &self,
        _request: tonic::Request<tonic::Streaming<orc_access::ForwardFrame>>,
    ) -> Result<tonic::Response<Self::ForwardStream>, tonic::Status> {
        unimplemented!()
    }
}

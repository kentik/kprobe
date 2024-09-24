include!(concat!(env!("OUT_DIR"), "/schema.rs"));

use tonic::{Request, Response};

pub use kentik::kagent::v202312::CapabilityState;
pub use kentik::kagent::v202312::{GatherMetricsRequest, GatherMetricsResponse};
pub use kentik::kagent::v202312::{ReloadConfigBundleRequest, ReloadConfigBundleResponse};
pub use kentik::kagent::v202312::{CapabilityStateRequest, CapabilityStateResponse};
pub use kentik::kagent::v202312::capability_state::Health;
pub use kentik::kagent::v202312::supervised_service_server::SupervisedService;
pub use kentik::kagent::v202312::supervised_service_server::SupervisedServiceServer;

pub type GatherRequest  = Request<GatherMetricsRequest>;
pub type GatherResponse = Response<GatherMetricsResponse>;
pub type ReloadRequest  = Request<ReloadConfigBundleRequest>;
pub type ReloadResponse = Response<ReloadConfigBundleResponse>;
pub type StateRequest   = Request<CapabilityStateRequest>;
pub type StateResponse  = Response<CapabilityStateResponse>;

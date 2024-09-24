use std::thread::{JoinHandle, spawn};
use anyhow::Result;
use log::{debug, error};
use tokio::net::UnixListener;
use tokio::runtime::Builder;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{Response, Status};
use tonic::transport::Server;
use crate::schema::{CapabilityState, CapabilityStateResponse};
use crate::schema::{GatherRequest, GatherResponse};
use crate::schema::{ReloadRequest, ReloadResponse};
use crate::schema::{StateRequest, StateResponse, Health};
use crate::schema::{SupervisedService, SupervisedServiceServer};

#[derive(Clone)]
pub struct Service;

impl Service {
    fn start(socket: String) -> Result<()> {
        let rt = Builder::new_current_thread().enable_all().build()?;
        rt.block_on(Self::exec(socket))
    }

    async fn exec(socket: String) -> Result<()> {
        debug!("server at {socket}");

        let socket = UnixListener::bind(socket)?;
        let stream = UnixListenerStream::new(socket);

        let service = SupervisedServiceServer::new(Self);
        let builder = Server::builder().add_service(service);

        Ok(builder.serve_with_incoming(stream).await?)
    }
}

#[tonic::async_trait]
impl SupervisedService for Service {
    async fn gather_metrics(&self, _: GatherRequest) -> Result<GatherResponse, Status> {
        Ok(Response::new(Default::default()))
    }

    async fn reload_config_bundle(&self, _: ReloadRequest) -> Result<ReloadResponse, Status> {
        Ok(Response::new(Default::default()))
    }

    async fn capability_state(&self, _: StateRequest) -> Result<StateResponse, Status> {
        Ok(Response::new(CapabilityStateResponse {
            state: Some(CapabilityState {
                status: Health::Ok.into(),
                ..Default::default()
            })
        }))
    }
}

pub fn start(socket: String) -> JoinHandle<()> {
    spawn(move || {
        match Service::start(socket) {
            Ok(()) => debug!("server finished"),
            Err(e) => error!("server error: {e:?}"),
        }
    })
}

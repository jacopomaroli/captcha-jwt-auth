use futures::future::{ok, Ready};
use std::sync::Arc;
use std::task::{Context, Poll};

use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    web::Data,
    Error, HttpMessage,
};

use crate::request_id_middleware::RequestID;
use crate::State;

pub struct ReqLoggerWrapper;

impl<S, B> Transform<S, ServiceRequest> for ReqLoggerWrapper
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = ReqLoggerMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(ReqLoggerMiddleware { service })
    }
}

pub struct ReqLoggerMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for ReqLoggerMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = S::Future;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let request_id_str = req.extensions().get::<RequestID>().unwrap().0.clone();
        let state: &Data<Arc<State>> = req.app_data::<Data<Arc<State>>>().unwrap();

        let req_logger = state.logger.new(o!("requestId" => request_id_str));

        req.extensions_mut().insert(req_logger);
        self.service.call(req)
    }
}

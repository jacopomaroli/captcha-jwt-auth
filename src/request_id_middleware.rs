use futures::future::{err, ok, Ready};
use std::task::{Context, Poll};

use uuid::Uuid;

use actix_web::{
    dev,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorBadRequest,
    Error, FromRequest, HttpMessage, HttpRequest,
};

pub struct RequestIdWrapper;

impl<S, B> Transform<S, ServiceRequest> for RequestIdWrapper
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = RequestIdMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RequestIdMiddleware { service })
    }
}

pub struct RequestIdMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RequestIdMiddleware<S>
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
        let request_id: String = Uuid::new_v4().to_string();

        req.extensions_mut().insert(RequestID(request_id));

        self.service.call(req)
    }
}

pub struct RequestID(pub String);

impl FromRequest for RequestID {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut dev::Payload) -> Self::Future {
        if let Some(RequestID(req_id)) = req.extensions().get::<RequestID>() {
            ok(RequestID(req_id.clone()))
        } else {
            err(ErrorBadRequest("RequestID is missing"))
        }
    }
}

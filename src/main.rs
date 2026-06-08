use axum::{
    Router,
    routing::{get, post},
};
use redis::aio::MultiplexedConnection;
use tracing::info;

use crate::{
    api::{
        key::{key_queues::KeyQM, key_handlers::get_public_key}, token::token_handlers::{
            generate_tokens, refresh_token, revoke_refresh_token, verify_access_token,
        }
    },
    application::services::{key::key_manager::KeyManager, token::token_manager::TokenManager},
    infrastructure::{queues::rabbitmq::rabbitmq::RabbitMQ, token::{
        jwks::{jwks_provider::JwksTokenProvider, jwks_validator::JwksTokenValidator},
        opaque::opaque_provider::GetrandomOpaqueTokenProvider,
    }},
};

mod api;
mod application;
mod domain;
mod infrastructure;

#[derive(Clone)]
pub struct AppState {
    pub key_manager: KeyManager,
    pub token_manager: TokenManager<
        JwksTokenProvider,
        JwksTokenValidator,
        GetrandomOpaqueTokenProvider,
        MultiplexedConnection,
    >,
}

impl AppState {
    pub fn new(conn: MultiplexedConnection) -> Result<Self, Box<dyn std::error::Error>> {
        let key_folder = "keys";

        let access_provider = JwksTokenProvider;
        let access_validator = JwksTokenValidator;
        let refresh_provider = GetrandomOpaqueTokenProvider;

        let key_manager = KeyManager::new(key_folder)?;
        let token_manager = TokenManager::new(
            access_provider,
            access_validator,
            refresh_provider,
            key_folder,
            conn,
        )?;

        Ok(Self {
            key_manager: key_manager,
            token_manager: token_manager,
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    tracing::info!("Tracing started");

    dotenvy::dotenv().ok();
    tracing::info!("Env files provided");

    dotenvy::dotenv().ok();

    let redis_client = redis::Client::open(std::env::var("REDIS_URL")?)?;
    let connection = redis_client.get_multiplexed_async_connection().await?;
    tracing::info!("Redis connected successfully");

    let rabbitmq = RabbitMQ::new(&std::env::var("RABBITMQ_URL")?)?;
    tracing::info!("RabbitMQ connected successfully");

    let rabbit_channel = rabbitmq.declare_channel().await?;

    let state = AppState::new(connection)?;

    let key_qm = KeyQM::new(rabbit_channel);

    state.key_manager.provide()?;
    tracing::info!("Public pem provided to file");

    key_qm.provide_public_key(state.key_manager.get_public()?).await?;
    tracing::info!("Public pem provided to RabbitMQ");

    let app = Router::new()
        .route("/", get(|| async { "Hello world!" }))
        .route("/key/public", get(get_public_key))
        .route("/generate", post(generate_tokens))
        .route("/verify", post(verify_access_token))
        .route("/refresh", post(refresh_token))
        .route("/revoke_refresh", post(revoke_refresh_token))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:5000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

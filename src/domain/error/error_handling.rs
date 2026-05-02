use tracing::error;

pub fn log_err<E: std::error::Error>(error: E) -> E {
    error!("Error: {}", error);

    error
}

use std::sync::Arc;

use lapin::{BasicProperties, Channel, Confirmation, Queue, options::{BasicPublishOptions, QueueDeclareOptions}, types::{FieldTable, ShortString}};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct RabbitMQueue {
    channel: Arc<Channel>,
    queue: Arc<Queue>,
    name: String,
}

#[derive(Debug, Error)]
pub enum RabbitMQueueError {
    #[error("Confirmation error: {0}")]
    Confirmation(String),

    #[error("RabbitMQ error: {0}")]
    Rabbit(#[from] lapin::Error),
}

impl RabbitMQueue {
    pub async fn new(channel: Arc<Channel>, name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let queue = Arc::new(channel.queue_declare(name.into(), QueueDeclareOptions::durable(), FieldTable::default()).await?);

        Ok(Self { channel, queue, name: name.to_string() })
    }

    pub async fn publish<Exchange: Into<ShortString>, Payload: AsRef<[u8]>>(&self, exchange: Exchange, payload: Payload) -> Result<Confirmation, RabbitMQueueError> {
        let confirm = self.channel.basic_publish(exchange.into(), self.name.as_str().into(), BasicPublishOptions::default(), payload.as_ref(), BasicProperties::default()).await?;

        match confirm.await? {
            Confirmation::Ack(ack) => {
                Ok(Confirmation::Ack(ack))
            }
            Confirmation::Nack(_) => {
                Err(RabbitMQueueError::Confirmation("Rabbit didn't confirm".to_string()))
            }
            Confirmation::NotRequested => {
                Err(RabbitMQueueError::Confirmation("Channel isn't ready".to_string()))
            }
        }

    }
}

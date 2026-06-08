use std::sync::Arc;
use tokio::sync::Mutex;

use async_rs::{Runtime, Tokio, traits::*};
use futures_lite::stream::StreamExt;
use lapin::{Channel, Consumer, options::BasicAckOptions, types::FieldTable};


#[derive(Debug, Clone)]
pub struct RabbitMQConsumer {
    consumer: Arc<Mutex<Consumer>>,
    tag: String,
    queue_name: String,
}

impl RabbitMQConsumer {
    pub async fn new(channel: Arc<Channel>, tag: &str, queue_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let consumer = Arc::new(Mutex::new(channel.basic_consume(queue_name.into(), tag.into(), lapin::options::BasicConsumeOptions::default(), FieldTable::default()).await?));

        Ok(Self { consumer, tag: tag.to_string(), queue_name: queue_name.to_string() })
    }

    pub async fn consume(&self, runtime: Arc<Runtime<Tokio>>) -> Result<(), Box<dyn std::error::Error>> {
        let consumer = self.consumer.clone();

        runtime.spawn(async move {
            while let Some(delivery) = consumer.lock().await.next().await {
                let delivery = delivery.expect("consumer error");
                delivery.ack(BasicAckOptions::default()).await.expect("ack");
            }
        });

        Ok(())
    }
}

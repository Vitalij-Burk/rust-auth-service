use std::sync::Arc;
use tokio::sync::Mutex;

use async_rs::{Runtime, Tokio, traits::*};
use lapin::{Channel, Connection, ConnectionProperties};

use crate::infrastructure::queues::rabbitmq::{consumer::consumer::RabbitMQConsumer, queue::queue::RabbitMQueue};

#[derive(Debug, Clone)]
pub struct RabbitMQ {
    runtime: Arc<Runtime<Tokio>>,
    connection: Arc<Connection>,
    channels: Arc<Mutex<Vec<Arc<Mutex<RabbitMQChannel>>>>>
}

impl RabbitMQ {
    pub fn new(addr: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let runtime = lapin::runtime::default_runtime()?;

        runtime.clone().block_on(async move {
            let connection = Arc::new(Connection::connect_with_runtime(&addr, ConnectionProperties::default(), runtime.clone()).await?);

            Ok(Self { runtime: Arc::new(runtime), connection, channels: Arc::new(Mutex::new(vec![])) })
        })
    }

    pub async fn declare_channel(&self) -> Result<Arc<Mutex<RabbitMQChannel>>, Box<dyn std::error::Error>> {
        let channel = Arc::new(Mutex::new(RabbitMQChannel::new(self.connection.clone()).await?));

        tracing::info!("RabbitMQ channel declared");

        self.channels.lock().await.push(channel.clone());

        Ok(channel)
    }
}

#[derive(Debug, Clone)]
pub struct RabbitMQChannel {
    channel: Arc<Channel>,
    consumers: Arc<Mutex<Vec<Arc<Mutex<RabbitMQConsumer>>>>>,
    queues: Arc<Mutex<Vec<Arc<Mutex<RabbitMQueue>>>>>,
}

impl RabbitMQChannel {
    pub async fn new(connection: Arc<Connection>) -> Result<Self, Box<dyn std::error::Error>> {
        let channel = Arc::new(connection.create_channel().await?);

        Ok(Self { channel, consumers: Arc::new(Mutex::new(vec![])), queues: Arc::new(Mutex::new(vec![])) })
    }

    pub async fn declare_consumer(&self, queue_name: &str, tag: &str) -> Result<Arc<Mutex<RabbitMQConsumer>>, Box<dyn std::error::Error>> {
        let consumer = Arc::new(Mutex::new(RabbitMQConsumer::new(self.channel.clone(), &tag, &queue_name).await?));

        tracing::info!("RabbitMQ consumer declared");

        self.consumers.lock().await.push(consumer.clone());

        Ok(consumer)
    }

    pub async fn declare_queue(&self, name: &str) -> Result<Arc<Mutex<RabbitMQueue>>, Box<dyn std::error::Error>> {
        let queue = Arc::new(Mutex::new(RabbitMQueue::new(self.channel.clone(), &name).await?));

        tracing::info!("RabbitMQ queue declared");

        self.queues.lock().await.push(queue.clone());

        Ok(queue)
    }
}

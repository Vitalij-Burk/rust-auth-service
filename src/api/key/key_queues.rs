use std::sync::Arc;

use tokio::sync::Mutex;

use crate::{infrastructure::queues::rabbitmq::rabbitmq::RabbitMQChannel};

pub struct KeyQM {
    rabbit_channel: Arc<Mutex<RabbitMQChannel>>
}

impl KeyQM {
    pub fn new(channel: Arc<Mutex<RabbitMQChannel>>) -> Self {
        Self { rabbit_channel: channel }
    }

    pub async fn provide_public_key<T>(
        &self,
        public_key: T
    ) -> Result<(), Box<dyn std::error::Error>>
    where 
        T: AsRef<[u8]>,
    {
        let channel = self.rabbit_channel.lock().await;

        let queue = channel.declare_queue("public_key").await?;
        let queue = queue.lock().await;

        queue.publish("key", public_key).await?;

        Ok(())
    }
}


#[derive(Debug, Clone, Copy)]
pub struct RedisIO<Storage> {
    redis_storage: Storage,
}

impl<Storage> RedisIO<Storage>
where
    Storage: redis::AsyncCommands + Send + Sync,
{
    pub fn new(storage: Storage) -> Self {
        Self {
            redis_storage: storage,
        }
    }

    pub async fn setex(
        &mut self,
        key: &str,
        data: &str,
        exp: u64,
    ) -> Result<(), redis::RedisError> {
        self.redis_storage
            .set_ex::<&str, String, ()>(&key, data.to_string(), exp)
            .await?;

        Ok(())
    }

    pub async fn get(&mut self, key: &str) -> Result<String, redis::RedisError> {
        let data = self.redis_storage.get::<&str, String>(&key).await?;

        Ok(data)
    }

    pub async fn delete(&mut self, key: &str) -> Result<(), redis::RedisError> {
        self.redis_storage.del::<&str, ()>(&key).await?;

        Ok(())
    }
}

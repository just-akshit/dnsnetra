# Kafka

The local development stack expects Kafka on `localhost:9092` and the topic `dns-logs`. The pipeline and Fluent Bit configuration use those names.

```bash
$KAFKA/bin/kafka-topics.sh --bootstrap-server localhost:9092 \
  --create --if-not-exists --topic dns-logs --partitions 1 --replication-factor 1
```

`scripts/development/start_all.sh` starts ZooKeeper and Kafka from `~/kafka` if they are not already listening. Production Kafka configuration is environment-specific and is not checked in; keep broker settings in the deployment host's configuration management.

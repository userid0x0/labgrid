# Run a automated test
Run a automated test (see `client/test.sh`) and shutdown the stack when finished.
```bash
cd <>
docker compose \
  -f ../../harness-base/docker-compose.yml \
  -f docker-compose.usage_example.yml \
  up --abort-on-container-exit
```

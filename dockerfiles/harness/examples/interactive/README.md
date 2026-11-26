# Run `labgrid-client` interactively
Open up a interactive shell for labgrid-client using the `harness-base` standard deployment.
```bash
cd <>
docker compose \
  -f ../../harness-base/docker-compose.yml \
  run client
```
#
```bash
docker compose \
   -f ../../harness-base/docker-compose.yml \
   -f docker-compose.override.client_debugpy.yml \
   run --service-ports client

cd /labgrid
pip install --editable .
pip install debugpy
debugpy --listen 0.0.0.0:5678 --wait-for-client $(which labgrid-client) r

```

### `launch.json`
```json
{
    "version": "0.2.0",
    "configurations": [

        {
            "name": "Python Debugger: Remote Attach",
            "type": "debugpy",
            "request": "attach",
            "connect": {
                "host": "127.0.0.1",
                "port": 5678
            },
            "pathMappings": [
                {
                    "localRoot": "${workspaceFolder}",
                    "remoteRoot": "/labgrid"
                }
            ]
        }
    ]
}
```
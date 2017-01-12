# Perforce exporter for Prometheus

Exports basic information about a remote Perforce server on port 8666

    http://localhost:8666/metrics

## Configuration

Configuration is done through traditional Perforce mechanisms. You can either
use environment variables or a local `.p4config` file

| Variable | Meaning                                                       |
| -------- | ------------------------------------------------------------- |
| P4PORT   | Required: address and port of the P4 server, i.e. server:1666 |
| P4USER   | Required: username                                            |
| P4PASSWD | Required: password or token                                   |

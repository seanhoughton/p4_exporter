# Perforce exporter for Prometheus

Exports basic information about a remote Perforce server on port 9666. 

    http://localhost:9666/metrics?target=perforce:1666&collectors=users,workspaces,depots


## Authentication/Credentials

Credentials are set up in the config file located at /etc/p4_exporter/conf.yml.

    credentials:
      perforce1.mydomain.com:1666:
        username: user1
        password: mybirthday
      perforce2.mydomain.com:1666:
        username: user2
        password: mypetsname


## Query Parameters

| Parameter  | Meaning                                               |
| ---------- | ----------------------------------------------------- |
| target     | address and port of the P4 server, i.e. server:1666   |
| collectors | command delimited list of optional collectors         |


### Collectors

With no credentials you'll get connection time information. If you add credentials you'll also get some basic
information about the server (uptime, etc.). If you want more details statistics you can provide an additional
"collectors" argument with a comma delimited list of collector names.

| Collector   | Data                                              |
| ---------   | ------------------------------------------------- |
| users       | Aggregate data about users                        |
| workspaces  | Aggregate data about workspaces                   |
| depots      | Information for each depot about size and usage   |
| replication | Aggregate data about journal and file replication |



## Example configuration

Add a scrape target to `prometheus.yml` which sends target queries to the p4-exporter

    - job_name: 'perforce'
      metrics_path: /probe
      scrape_interval: 30s
      scrape_timeout: 10s
      params:
        module: [tcp_connect]
      file_sd_configs:
        - files: [perforce.yml]
      relabel_configs:
        - source_labels: [__address__]
          regex: (.*)
          target_label: __param_target
          replacement: ${1}
        - source_labels: [__param_target]
          regex: (.*):\d+
          target_label: instance
          replacement: ${1}
        - source_labels: []
          regex: .*
          target_label: __address__
          replacement: p4-exporter:9666
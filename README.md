# Perforce exporter for Prometheus

Exports basic information about a remote Perforce server on port 9666. 

    http://localhost:9666/metrics?port=perforce:1666&username=myuser&password=mypass


## Query Parameters


| Parameter | Meaning                                             |
| --------- | --------------------------------------------------- |
| port      | address and port of the P4 server, i.e. server:1666 |
| username  | username                                            |
| password  | password or token                                   |


## Target configuration



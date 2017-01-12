# Perforce exporter for Prometheus

Exports basic information about a remote Perforce server on port 9666. 

    http://localhost:9666/metrics?port=perforce:1666&username=myuser


## Authentication/Credentials

Credentials for servers can be passed in on the command line or as the `P4EXP_CREDENTIALS` environment variable. A credential must exist for all queried servers.

    p4exporter.py -c foo:bar@perforce1,jar:car@perforce2


## Query Parameters


| Parameter | Meaning                                             |
| --------- | --------------------------------------------------- |
| port      | address and port of the P4 server, i.e. server:1666 |
| username  | username                                            |


## Target configuration



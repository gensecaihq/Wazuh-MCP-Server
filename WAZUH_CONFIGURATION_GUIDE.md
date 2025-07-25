# Wazuh Configuration Guide for MCP Server

This guide provides comprehensive instructions for configuring your Wazuh infrastructure to work optimally with the Wazuh MCP Server.

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Wazuh Server Configuration](#wazuh-server-configuration)
- [Wazuh Indexer Configuration](#wazuh-indexer-configuration)
- [API User Setup](#api-user-setup)
- [SSL/TLS Configuration](#ssltls-configuration)
- [Network Configuration](#network-configuration)
- [Performance Tuning](#performance-tuning)
- [Security Hardening](#security-hardening)
- [Troubleshooting](#troubleshooting)

---

## 🔧 Prerequisites

### Wazuh Infrastructure Requirements

- **Wazuh Manager**: 4.8+ (recommended: 4.9+)
- **Wazuh Indexer**: 4.8+ (optional but recommended for distributed setups)
- **Operating System**: Linux (CentOS, Ubuntu, RHEL, Debian)
- **Memory**: Minimum 4GB RAM (8GB+ recommended for production)
- **Storage**: SSD recommended, 50GB+ free space
- **Network**: HTTPS connectivity between components

### Supported Wazuh Architectures

1. **Single-Node**: Wazuh Manager + Indexer on same server
2. **Distributed**: Separate Wazuh Manager and Indexer servers
3. **Multi-Node**: Clustered Wazuh Managers with distributed Indexers

---

## 🖥️ Wazuh Server Configuration

### 1. Enable Wazuh API

Edit `/var/ossec/api/configuration/api.yaml`:

```yaml
# Wazuh API Configuration for MCP Server
# /var/ossec/api/configuration/api.yaml

host: 0.0.0.0  # Listen on all interfaces
port: 55000    # Standard Wazuh API port
use_only_authd: false
drop_privileges: true
experimental_features: false

# HTTPS Configuration (Recommended)
https:
  enabled: true
  key: "/var/ossec/api/configuration/ssl/server.key"
  cert: "/var/ossec/api/configuration/ssl/server.crt"
  use_ca: false
  ca: "/var/ossec/api/configuration/ssl/ca.crt"
  ssl_protocol: "TLSv1.2"
  ssl_ciphers: ""

# CORS Configuration for web access
cors:
  enabled: true
  source_route: "*"
  expose_headers: "*"
  allow_headers: "*"
  allow_credentials: false

# Cache Configuration
cache:
  enabled: true
  time: 0.750

# Authentication
security:
  auth_token_exp_timeout: 900
  rbac_mode: "white"

# Logging
logs:
  level: "INFO"  # DEBUG for troubleshooting
  path: "/var/ossec/logs/api.log"
  max_size:
    enabled: true
    size: "1MB"
  rotate:
    enabled: true
    max_files: 10

# Upload limits
upload:
  max_upload_size: "10MB"

# Performance
max_upload_size: "10MB"
max_request_per_minute: 300
request_timeout: 30
```

### 2. Configure Wazuh Manager

Edit `/var/ossec/etc/ossec.conf`:

```xml
<!-- Wazuh Manager Configuration for MCP Server -->
<!-- /var/ossec/etc/ossec.conf -->

<ossec_config>
  <!-- Global settings -->
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>localhost</smtp_server>
    <email_from>wazuh@your-domain.com</email_from>
    <email_to>admin@your-domain.com</email_to>
    <hostname>wazuh-manager</hostname>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <agents_disconnection_time>10m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
  </global>

  <!-- Rules configuration -->
  <rules>
    <include>rules_config.xml</include>
    <include>pam_rules.xml</include>
    <include>sshd_rules.xml</include>
    <include>telnetd_rules.xml</include>
    <include>syslog_rules.xml</include>
    <include>arpwatch_rules.xml</include>
    <include>symantec-av_rules.xml</include>
    <include>symantec-ws_rules.xml</include>
    <include>pix_rules.xml</include>
    <include>named_rules.xml</include>
    <include>smbd_rules.xml</include>
    <include>vsftpd_rules.xml</include>
    <include>pure-ftpd_rules.xml</include>
    <include>proftpd_rules.xml</include>
    <include>ms_ftpd_rules.xml</include>
    <include>ftpd_rules.xml</include>
    <include>hordeimp_rules.xml</include>
    <include>roundcube_rules.xml</include>
    <include>wordpress_rules.xml</include>
    <include>cimserver_rules.xml</include>
    <include>vpopmail_rules.xml</include>
    <include>vmpop3d_rules.xml</include>
    <include>courier_rules.xml</include>
    <include>web_rules.xml</include>
    <include>web_appsec_rules.xml</include>
    <include>apache_rules.xml</include>
    <include>nginx_rules.xml</include>
    <include>php_rules.xml</include>
    <include>mysql_rules.xml</include>
    <include>postgresql_rules.xml</include>
    <include>ids_rules.xml</include>
    <include>squid_rules.xml</include>
    <include>firewall_rules.xml</include>
    <include>cisco-ios_rules.xml</include>
    <include>netscreenfw_rules.xml</include>
    <include>sonicwall_rules.xml</include>
    <include>postfix_rules.xml</include>
    <include>sendmail_rules.xml</include>
    <include>imapd_rules.xml</include>
    <include>mailscanner_rules.xml</include>
    <include>dovecot_rules.xml</include>
    <include>ms-exchange_rules.xml</include>
    <include>racoon_rules.xml</include>
    <include>vpn_concentrator_rules.xml</include>
    <include>spamd_rules.xml</include>
    <include>msauth_rules.xml</include>
    <include>mcafee_av_rules.xml</include>
    <include>trend-osce_rules.xml</include>
    <include>ms-se_rules.xml</include>
    <include>zeus_rules.xml</include>
    <include>solaris_bsm_rules.xml</include>
    <include>vmware_rules.xml</include>
    <include>ms_dhcp_rules.xml</include>
    <include>asterisk_rules.xml</include>
    <include>ossec_rules.xml</include>
    <include>attack_rules.xml</include>
    <include>local_rules.xml</include>
  </rules>

  <!-- Syscheck (File Integrity Monitoring) -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <auto_ignore>no</auto_ignore>
    <alert_new_files>yes</alert_new_files>
    <remove_old_diff>yes</remove_old_diff>
    <restart_audit>yes</restart_audit>
    
    <!-- Directories to monitor -->
    <directories>/etc,/usr/bin,/usr/sbin</directories>
    <directories>/bin,/sbin,/boot</directories>
    
    <!-- Files to ignore -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
  </syscheck>

  <!-- Rootcheck -->
  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
    <rootkit_files>/var/ossec/etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/shared/rootkit_trojans.txt</rootkit_trojans>
    <system_audit>/var/ossec/etc/shared/system_audit_rcl.txt</system_audit>
    <system_audit>/var/ossec/etc/shared/system_audit_ssh.txt</system_audit>
    <system_audit>/var/ossec/etc/shared/cis_debian_linux_rcl.txt</system_audit>
    <system_audit>/var/ossec/etc/shared/cis_rhel_linux_rcl.txt</system_audit>
    <system_audit>/var/ossec/etc/shared/cis_rhel5_linux_rcl.txt</system_audit>
  </rootcheck>

  <!-- Log analysis global options -->
  <global>
    <white_list>127.0.0.1</white_list>
    <white_list>^localhost.localdomain$</white_list>
    <white_list>10.0.0.0/8</white_list>
    <white_list>172.16.0.0/12</white_list>
    <white_list>192.168.0.0/16</white_list>
  </global>

  <!-- Remote connection -->
  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <allowed-ips>0.0.0.0/0</allowed-ips>
  </remote>

  <!-- Authentication daemon -->
  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <purge>yes</purge>
    <use_password>yes</use_password>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <ssl_agent_ca>/var/ossec/etc/sslmanager.cert</ssl_agent_ca>
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>/var/ossec/etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>/var/ossec/etc/sslmanager.key</ssl_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>

  <!-- Cluster configuration -->
  <cluster>
    <name>wazuh</name>
    <node_name>master-node</node_name>
    <node_type>master</node_type>
    <key>your-cluster-key-here</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
      <node>wazuh-master</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>yes</disabled>
  </cluster>

  <!-- Vulnerability detector -->
  <vulnerability-detector>
    <enabled>yes</enabled>
    <interval>5m</interval>
    <min_full_scan_interval>6h</min_full_scan_interval>
    <run_on_start>yes</run_on_start>

    <!-- Operating systems vulnerabilities -->
    <provider name="canonical">
      <enabled>yes</enabled>
      <os>trusty</os>
      <os>xenial</os>
      <os>bionic</os>
      <os>focal</os>
      <os>jammy</os>
      <update_interval>1h</update_interval>
    </provider>

    <provider name="debian">
      <enabled>yes</enabled>
      <os>wheezy</os>
      <os>stretch</os>
      <os>jessie</os>
      <os>buster</os>
      <os>bullseye</os>
      <update_interval>1h</update_interval>
    </provider>

    <provider name="redhat">
      <enabled>yes</enabled>
      <os>5</os>
      <os>6</os>
      <os>7</os>
      <os>8</os>
      <os>9</os>
      <update_interval>1h</update_interval>
    </provider>

    <provider name="nvd">
      <enabled>yes</enabled>
      <update_interval>1h</update_interval>
    </provider>
  </vulnerability-detector>

  <!-- CIS-CAT integration -->
  <wodle name="cis-cat">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>
    <java_path>wodles/java</java_path>
    <ciscat_path>wodles/ciscat</ciscat_path>
  </wodle>

  <!-- Osquery integration -->
  <wodle name="osquery">
    <disabled>yes</disabled>
    <run_daemon>yes</run_daemon>
    <log_path>/var/log/osquery/osqueryd.results.log</log_path>
    <config_path>/etc/osquery/osquery.conf</config_path>
    <add_labels>yes</add_labels>
  </wodle>

  <!-- Syscollector -->
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
    <hotfixes>yes</hotfixes>
  </wodle>

  <!-- SCA Configuration assessment -->
  <wodle name="sca">
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
  </wodle>

  <!-- Active response -->
  <global>
    <ar_disabled>no</ar_disabled>
  </global>

  <command>
    <name>disable-account</name>
    <executable>disable-account.sh</executable>
    <expect>user</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>restart-ossec</name>
    <executable>restart-ossec.sh</executable>
    <expect></expect>
  </command>

  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>host-deny</name>
    <executable>host-deny.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>route-null</name>
    <executable>route-null.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>win_route-null</name>
    <executable>route-null.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>netsh</name>
    <executable>netsh.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <!-- Active Response Rules -->
  <active-response>
    <disabled>no</disabled>
    <command>host-deny</command>
    <location>local</location>
    <rules_id>5712</rules_id>
    <timeout>600</timeout>
  </active-response>

  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5712</rules_id>
    <timeout>600</timeout>
  </active-response>

</ossec_config>
```

### 3. Restart Wazuh Services

```bash
# Restart Wazuh Manager
sudo systemctl restart wazuh-manager

# Restart Wazuh API
sudo systemctl restart wazuh-api

# Check service status
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-api
```

---

## 🔍 Wazuh Indexer Configuration

### 1. Indexer Settings

Edit `/etc/wazuh-indexer/opensearch.yml`:

```yaml
# Wazuh Indexer Configuration for MCP Server
# /etc/wazuh-indexer/opensearch.yml

cluster.name: wazuh-cluster
node.name: wazuh-indexer-node-1
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer

# Network configuration
network.host: 0.0.0.0
http.port: 9200
transport.tcp.port: 9300

# Discovery configuration for single node
discovery.type: single-node

# Security
plugins.security.ssl.transport.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.transport.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.http.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem

# Authentication
plugins.security.authcz.admin_dn:
  - "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"

# Performance tuning
indices.memory.index_buffer_size: 10%
indices.fielddata.cache.size: 20%
indices.queries.cache.size: 10%

# Thread pools
thread_pool.search.size: 30
thread_pool.search.queue_size: 1000
thread_pool.index.size: 30
thread_pool.index.queue_size: 200

# JVM heap size (adjust based on available memory)
# Set in /etc/wazuh-indexer/jvm.options:
# -Xms2g
# -Xmx2g

# Cluster settings (for multi-node setup)
# cluster.initial_master_nodes: ["wazuh-indexer-node-1"]
# discovery.seed_hosts: ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

# Index settings
action.auto_create_index: true
action.destructive_requires_name: true

# Monitoring
cluster.routing.allocation.disk.threshold_enabled: true
cluster.routing.allocation.disk.watermark.low: 85%
cluster.routing.allocation.disk.watermark.high: 90%
cluster.routing.allocation.disk.watermark.flood_stage: 95%

# Compression
index.codec: best_compression

# Memory settings
bootstrap.memory_lock: true

# Logging
logger.level: INFO
```

### 2. Index Templates for Wazuh Data

Create optimized index templates:

```bash
# Create index template for alerts
curl -X PUT "https://your-indexer:9200/_index_template/wazuh-alerts" \
  -u admin:admin \
  -k \
  -H "Content-Type: application/json" \
  -d '{
    "index_patterns": ["wazuh-alerts-*"],
    "template": {
      "settings": {
        "index": {
          "number_of_shards": 1,
          "number_of_replicas": 0,
          "refresh_interval": "5s",
          "codec": "best_compression"
        }
      },
      "mappings": {
        "properties": {
          "@timestamp": {
            "type": "date"
          },
          "agent": {
            "properties": {
              "id": {"type": "keyword"},
              "name": {"type": "keyword"},
              "ip": {"type": "ip"}
            }
          },
          "rule": {
            "properties": {
              "id": {"type": "long"},
              "level": {"type": "long"},
              "description": {"type": "text"}
            }
          }
        }
      }
    }
  }'

# Create index template for vulnerabilities
curl -X PUT "https://your-indexer:9200/_index_template/wazuh-vulnerabilities" \
  -u admin:admin \
  -k \
  -H "Content-Type: application/json" \
  -d '{
    "index_patterns": ["wazuh-vulnerabilities-*"],
    "template": {
      "settings": {
        "index": {
          "number_of_shards": 1,
          "number_of_replicas": 0,
          "refresh_interval": "30s",
          "codec": "best_compression"
        }
      }
    }
  }'
```

---

## 👤 API User Setup

### 1. Create Dedicated API User

```bash
# Create MCP API user with appropriate permissions
curl -X POST "https://your-wazuh-server:55000/security/users" \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "mcp-api-user",
    "password": "your-secure-password-here"
  }'

# Create role for MCP operations
curl -X POST "https://your-wazuh-server:55000/security/roles" \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "mcp_role",
    "policy": {
      "actions": [
        "agent:read",
        "agent:restart",
        "alert:read",
        "vulnerability:read",
        "cluster:read",
        "manager:read",
        "statistics:read",
        "security:read"
      ],
      "resources": [
        "agent:id:*",
        "alert:id:*",
        "vulnerability:id:*",
        "cluster:node:*",
        "manager:configuration:*",
        "statistics:*",
        "security:*"
      ],
      "effect": "allow"
    }
  }'

# Assign role to user
curl -X POST "https://your-wazuh-server:55000/security/users/mcp-api-user/roles" \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "role_ids": ["mcp_role"]
  }'
```

### 2. Test API Access

```bash
# Test authentication
curl -X GET "https://your-wazuh-server:55000/security/user/authenticate" \
  -u mcp-api-user:your-secure-password-here \
  -k

# Test agent access
curl -X GET "https://your-wazuh-server:55000/agents" \
  -u mcp-api-user:your-secure-password-here \
  -k

# Test alerts access
curl -X GET "https://your-wazuh-server:55000/alerts" \
  -u mcp-api-user:your-secure-password-here \
  -k
```

---

## 🔒 SSL/TLS Configuration

### 1. Generate SSL Certificates

```bash
# Create certificate directory
sudo mkdir -p /var/ossec/api/configuration/ssl

# Generate private key
sudo openssl genrsa -out /var/ossec/api/configuration/ssl/server.key 4096

# Generate certificate signing request
sudo openssl req -new -key /var/ossec/api/configuration/ssl/server.key \
  -out /var/ossec/api/configuration/ssl/server.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=your-wazuh-server.com"

# Generate self-signed certificate (for testing)
sudo openssl x509 -req -days 365 \
  -in /var/ossec/api/configuration/ssl/server.csr \
  -signkey /var/ossec/api/configuration/ssl/server.key \
  -out /var/ossec/api/configuration/ssl/server.crt

# Set proper permissions
sudo chown -R wazuh:wazuh /var/ossec/api/configuration/ssl
sudo chmod 600 /var/ossec/api/configuration/ssl/server.key
sudo chmod 644 /var/ossec/api/configuration/ssl/server.crt
```

### 2. Configure Client Certificates (Optional)

```bash
# Generate client certificate for MCP Server
sudo openssl genrsa -out /var/ossec/api/configuration/ssl/client.key 4096
sudo openssl req -new -key /var/ossec/api/configuration/ssl/client.key \
  -out /var/ossec/api/configuration/ssl/client.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=mcp-client"
sudo openssl x509 -req -days 365 \
  -in /var/ossec/api/configuration/ssl/client.csr \
  -signkey /var/ossec/api/configuration/ssl/client.key \
  -out /var/ossec/api/configuration/ssl/client.crt
```

---

## 🌐 Network Configuration

### 1. Firewall Rules

```bash
# Wazuh Manager
sudo ufw allow 55000/tcp  # Wazuh API
sudo ufw allow 1514/tcp   # Agent communication
sudo ufw allow 1515/tcp   # Agent enrollment
sudo ufw allow 1516/tcp   # Cluster communication

# Wazuh Indexer
sudo ufw allow 9200/tcp   # REST API
sudo ufw allow 9300/tcp   # Node communication

# Apply rules
sudo ufw reload
```

### 2. Load Balancer Configuration (HAProxy Example)

```bash
# /etc/haproxy/haproxy.cfg
global
    log stdout local0
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    option httplog
    option dontlognull

# Wazuh API Load Balancing
frontend wazuh_api_frontend
    bind *:55000 ssl crt /etc/ssl/certs/wazuh.pem
    default_backend wazuh_api_backend

backend wazuh_api_backend
    balance roundrobin
    option httpchk GET /
    server wazuh1 10.0.0.10:55000 check ssl verify none
    server wazuh2 10.0.0.11:55000 check ssl verify none

# Wazuh Indexer Load Balancing
frontend wazuh_indexer_frontend
    bind *:9200 ssl crt /etc/ssl/certs/wazuh.pem
    default_backend wazuh_indexer_backend

backend wazuh_indexer_backend
    balance roundrobin
    option httpchk GET /_cluster/health
    server indexer1 10.0.0.20:9200 check ssl verify none
    server indexer2 10.0.0.21:9200 check ssl verify none
```

---

## ⚡ Performance Tuning

### 1. Wazuh Manager Tuning

Edit `/var/ossec/etc/local_internal_options.conf`:

```ini
# Wazuh Manager Performance Tuning
# /var/ossec/etc/local_internal_options.conf

# Analysis engine
analysisd.state_interval=300
analysisd.min_rotate_interval=600
analysisd.max_output_size=512

# Remote daemon
remoted.recv_counter_flush=128
remoted.comp_average_printout=19999
remoted.verify_msg_id=1

# Database
wdb.commit_time=60
wdb.worker_pool_size=8

# Logging
agent.debug_level=1
monitord.compress=1
monitord.day_wait=10
```

### 2. System-Level Optimization

```bash
# Increase file descriptor limits
echo "wazuh soft nofile 65536" >> /etc/security/limits.conf
echo "wazuh hard nofile 65536" >> /etc/security/limits.conf

# Optimize kernel parameters
cat >> /etc/sysctl.conf << EOF
# Network optimization
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 16384 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 300000

# File system optimization
fs.file-max = 2097152
vm.swappiness = 1
vm.dirty_ratio = 80
vm.dirty_background_ratio = 5
EOF

# Apply changes
sudo sysctl -p
```

---

## 🛡️ Security Hardening

### 1. API Security

```yaml
# Enhanced API security settings
# /var/ossec/api/configuration/api.yaml

security:
  auth_token_exp_timeout: 900
  rbac_mode: "white"
  max_login_attempts: 3
  block_time: 300
  max_request_per_minute: 100

# Request size limits
max_upload_size: "10MB"
request_timeout: 30

# Disable unnecessary endpoints
disable_endpoints:
  - "/manager/info"
  - "/cluster/healthcheck"
```

### 2. File Permissions

```bash
# Secure Wazuh files
sudo find /var/ossec -type f -name "*.conf" -exec chmod 640 {} \;
sudo find /var/ossec -type f -name "*.key" -exec chmod 600 {} \;
sudo find /var/ossec -type d -exec chmod 750 {} \;

# Secure API files
sudo chmod 600 /var/ossec/api/configuration/api.yaml
sudo chown wazuh:wazuh /var/ossec/api/configuration/api.yaml
```

### 3. Network Security

```bash
# Configure fail2ban for Wazuh API
cat > /etc/fail2ban/jail.local << EOF
[wazuh-api]
enabled = true
port = 55000
protocol = tcp
filter = wazuh-api
logpath = /var/ossec/logs/api.log
maxretry = 5
bantime = 3600
findtime = 600
EOF

# Create fail2ban filter
cat > /etc/fail2ban/filter.d/wazuh-api.conf << EOF
[Definition]
failregex = .*Authentication failed.*<HOST>.*
ignoreregex =
EOF

# Restart fail2ban
sudo systemctl restart fail2ban
```

---

## 🔧 Troubleshooting

### 1. Common Connection Issues

```bash
# Check Wazuh services
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-api
sudo systemctl status wazuh-indexer

# Check listening ports
sudo netstat -tlnp | grep -E "(55000|9200|1514|1515)"

# Test API connectivity
curl -k -u mcp-api-user:password https://your-wazuh-server:55000/

# Check logs
sudo tail -f /var/ossec/logs/api.log
sudo tail -f /var/ossec/logs/ossec.log
sudo tail -f /var/log/wazuh-indexer/wazuh-cluster.log
```

### 2. SSL Certificate Issues

```bash
# Verify certificate
openssl x509 -in /var/ossec/api/configuration/ssl/server.crt -text -noout

# Test SSL connection
openssl s_client -connect your-wazuh-server:55000 -servername your-wazuh-server

# Check certificate expiration
openssl x509 -in /var/ossec/api/configuration/ssl/server.crt -enddate -noout
```

### 3. Performance Issues

```bash
# Monitor Wazuh processes
top -p $(pgrep wazuh)

# Check disk usage
df -h /var/ossec
du -sh /var/ossec/logs/*

# Monitor network connections
ss -tulpn | grep -E "(55000|9200)"

# Check memory usage
free -h
cat /proc/meminfo | grep -E "(MemTotal|MemFree|MemAvailable)"
```

### 4. Debug Mode

```bash
# Enable debug logging
echo "wazuh.debug_level=2" >> /var/ossec/etc/local_internal_options.conf
sudo systemctl restart wazuh-manager

# Monitor debug logs
sudo tail -f /var/ossec/logs/ossec.log | grep -i debug
```

---

## 📞 Support and Additional Resources

- **Wazuh Documentation**: https://documentation.wazuh.com/
- **Wazuh Community**: https://wazuh.com/community/
- **GitHub Issues**: https://github.com/wazuh/wazuh/issues
- **MCP Server Issues**: https://github.com/gensecaihq/Wazuh-MCP-Server/issues

Remember to always test configurations in a development environment before applying to production systems.
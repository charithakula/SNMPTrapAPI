
# Flask SNMP Trap Sender with Prometheus Metrics

This is a Flask-based web application that combines network monitoring (via SNMP) with Prometheus metrics collection and exposure. It allows sending SNMP traps to a designated target (supporting both SNMPv2c and SNMPv3) and provides endpoints for Prometheus to scrape metrics related to HTTP request statistics. Additionally, it includes a health check endpoint to monitor the app's health.

### Key Features:
- **SNMP Trap Sending**: Allows sending SNMP traps based on provided JSON data. Supports both SNMPv2c and SNMPv3 authentication.
- **Prometheus Metrics**: Exposes HTTP request statistics such as request count and duration through a Prometheus-compatible endpoint.
- **Health Check**: Simple health check endpoint to confirm that the application is up and running.
- **Logging**: Provides detailed logging for debugging and monitoring the SNMP trap sending process.

The app is designed to be used in monitoring systems where SNMP traps need to be sent and Prometheus is used for metrics collection. It's ideal for use cases in IT infrastructure monitoring, alerting, and diagnostics.

## Features

- **Prometheus Metrics**: The app exposes two key Prometheus metrics:
  - `http_requests_total`: A counter of total HTTP requests made to the app.
  - `http_request_duration_seconds`: A histogram of the duration of HTTP requests, allowing for performance monitoring.
  
- **Health Check Endpoint**: A simple endpoint (`/health`) to check if the application is alive and functioning.
  
- **SNMP Trap Sender**: The app can send SNMP traps to a target server, allowing network administrators to be alerted of network events or anomalies. It supports both SNMPv2c and SNMPv3 with customizable security settings (e.g., authentication and privacy protocols).

- **Logging**: Every action within the app (e.g., sending SNMP traps or accessing endpoints) is logged for troubleshooting and auditing purposes.

## Requirements

The following Python packages are required to run the application:

- `Flask==3.1.0`
- `prometheus_client==0.21.1`
- `pysnmp==7.1.16`
- `pycryptodome==3.15.0`
- `Werkzeug==3.1.3`

You can install the dependencies using `pip`:

```bash
pip install Flask==3.1.0 prometheus_client==0.21.1 pysnmp==7.1.16 pycryptodome==3.15.0 Werkzeug==3.1.3
```

Alternatively, you can create a `requirements.txt` file with the following content and install all dependencies at once:

```
Flask==3.1.0
prometheus_client==0.21.1
pysnmp==7.1.16
pycryptodome==3.15.0
Werkzeug==3.1.3
```

Then install the dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

1. **SNMP Credentials**: The SNMP credentials (username, password, authentication protocol, privacy protocol, etc.) are loaded from a `credentials.json` file. The file should be structured as follows:

```json
{
  "snmpv3_user": "your_snmp_user",
  "auth_password": "your_auth_password",
  "priv_password": "your_priv_password",
  "auth_protocol": "SHA",
  "priv_protocol": "AES",
  "snmp_target_ip": "target_ip",
  "snmp_target_port": 162
}
```

2. **Prometheus Metrics**: The `/metrics` endpoint exposes metrics in a format compatible with Prometheus. It includes:
   - `http_requests_total`: A counter of total HTTP requests.
   - `http_request_duration_seconds`: A histogram of HTTP request durations.

## Endpoints

### **`/health` (GET)**
A simple health check endpoint.
- **Returns**: `OK`

### **`/metrics` (GET)**
Exposes Prometheus metrics for monitoring.
- **Returns**: Metrics in `text/plain` format for Prometheus scraping.

### **`/send_snmp_trap/` (POST)**
Accepts JSON data to send an SNMP trap. The expected request format is:

```json
{
  "source": "source_value",
  "severity": "severity_value",
  "timestamp": "timestamp_value",
  "message": "message_value",
  "application": "application_value",
  "region": "region_value"
}
```

#### Example Request:
```bash
curl -X POST http://localhost:8000/send_snmp_trap/ -H "Content-Type: application/json" -d '{"source": "server1", "severity": "critical", "timestamp": "2025-02-13T14:00:00Z", "message": "CPU high", "application": "app1", "region": "us-east"}'
```

#### Example Response:
```json
{
  "status": "success",
  "message": "SNMP Trap sent successfully"
}
```

## Running the Application

To run the Flask application, use the following command:

```bash
python app.py
```

By default, the app will run on `http://0.0.0.0:8000`. You can change the port and host by modifying the `app.run()` method.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
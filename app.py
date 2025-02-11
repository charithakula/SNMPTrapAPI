import json
from fastapi import FastAPI
from pydantic import BaseModel
from prometheus_client import Counter, generate_latest, CollectorRegistry
from prometheus_client.exposition import basic_auth_handler
from pysnmp.hlapi import *
import logging
from fastapi.responses import Response
from fastapi import Depends
from pysnmp.hlapi.v3arch.asyncio import *

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI()

# Initialize Prometheus metrics
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint'])
# You can add more Prometheus metrics based on your needs

# Load SNMP credentials from credentials.json
def load_snmp_credentials():
    with open('credentials.json') as f:
        return json.load(f)

credentials = load_snmp_credentials()

# Define the SNMP trap request model
class SNMPTrapRequest(BaseModel):
    source: str
    severity: str
    timestamp: str
    message: str
    application: str
    region: str

# Health Check Endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy"}

# Function to send SNMPv3 INFORM notification asynchronously
async def send_snmp_trap(oids):
    """Send SNMPv3 INFORM notification asynchronously."""
    # Load credentials for SNMPv3
    snmpv3_user = credentials['snmpv3_user']
    auth_password = credentials['auth_password']
    priv_password = credentials['priv_password']
    auth_protocol = credentials['auth_protocol']
    priv_protocol = credentials['priv_protocol']

    # Configure SNMPv3 settings
    if auth_protocol == "SHA":
        auth_protocol = usmHMACSHAAuthProtocol
    elif auth_protocol == "MD5":
        auth_protocol = usmHMACMD5AuthProtocol
    else:
        logger.error("Invalid authentication protocol")
        return {"status": "error", "message": "Invalid authentication protocol"}

    if priv_protocol == "AES":
        priv_protocol = usmAesCfb128Protocol
    elif priv_protocol == "DES":
        priv_protocol = usmDESPrivProtocol
    else:
        logger.error("Invalid privacy protocol")
        return {"status": "error", "message": "Invalid privacy protocol"}

    # Configure SNMPv3 settings
    auth_data = UsmUserData(
        snmpv3_user,
        authPassword=auth_password,
        privPassword=priv_password,
        authProtocol=auth_protocol,
        privProtocol=priv_protocol
    )

    # SNMP target configuration
    transport_target = await UdpTransportTarget.create(("demo.pysnmp.com", 162))  # Adjust target as needed
    context_data = ContextData()

    snmpEngine = SnmpEngine()

    # Send SNMP trap
    (
        errorIndication,
        errorStatus,
        errorIndex,
        varBindTable,
    ) = await send_notification(
        snmpEngine,
        auth_data,
        transport_target,
        context_data,
        "inform",  # NotifyType
        NotificationType(ObjectIdentity("SNMPv2-MIB", "coldStart")).add_varbinds(*oids),
    )

    if errorIndication:
        logger.error(f"Notification not sent: {errorIndication}")
        return {"status": "error", "message": f"Notification not sent: {errorIndication}"}
    elif errorStatus:
        logger.error(f"Notification Receiver returned error: {errorStatus} @{errorIndex}")
        return {"status": "error", "message": f"Receiver returned error: {errorStatus} @{errorIndex}"}
    else:
        logger.info("Notification delivered:")
        for name, val in varBindTable:
            logger.info(f"{name.prettyPrint()} = {val.prettyPrint()}")
        return {"status": "success", "message": "SNMP trap sent successfully"}

# FastAPI POST route to send SNMP traps
@app.post("/send_snmp_trap/")
async def api_send_snmp_trap(request: SNMPTrapRequest):
    oids = [
        ("1.3.6.1.4.1.12345.1.2.1", OctetString(request.source)),
        ("1.3.6.1.4.1.12345.1.2.2", OctetString(request.severity)),
        ("1.3.6.1.4.1.12345.1.2.3", OctetString(request.timestamp)),
        ("1.3.6.1.4.1.12345.1.2.4", OctetString(request.message)),
        ("1.3.6.1.4.1.12345.1.2.5", OctetString(request.application)),
        ("1.3.6.1.4.1.12345.1.2.6", OctetString(request.region))
    ]
    logger.info(f"📩 Trap request received: {request}")
    response = await send_snmp_trap(oids)
    return response

# Metrics Endpoint for Prometheus
@app.get("/metrics")
async def metrics():
    # Increment the request count for each incoming request
    REQUEST_COUNT.labels(method="GET", endpoint="/metrics").inc()
    
    # You can add more custom metrics logic here
    
    # Generate the latest metrics for Prometheus
    return Response(generate_latest(REQUEST_COUNT), media_type="text/plain")

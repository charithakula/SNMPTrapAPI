import json
from fastapi import FastAPI
from pydantic import BaseModel
from prometheus_client import Counter, generate_latest, CollectorRegistry
from prometheus_client.exposition import basic_auth_handler
from pysnmp.hlapi import *
import logging
from fastapi.responses import Response
from fastapi import Depends
import asyncio
from pysnmp.hlapi.v3arch.asyncio import *

# Set up logging
logging.basicConfig(level=logging.DEBUG)  # Change to DEBUG for more granular logs
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI()

# Initialize Prometheus metrics
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint'])

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
    logger.debug("Health check endpoint hit")
    return {"status": "healthy"}

# Function to send SNMP trap asynchronously
async def send_snmp_trap(oids):
    """Send SNMP trap asynchronously."""
    logger.debug(f"Preparing to send SNMP trap with OIDs: {oids}")
    
    # Load credentials for SNMPv3
    snmpv3_user = credentials['snmpv3_user']
    auth_password = credentials['auth_password']
    priv_password = credentials['priv_password']
    auth_protocol = credentials['auth_protocol']
    priv_protocol = credentials['priv_protocol']
    snmp_target_ip = credentials['snmp_target_ip']
    snmp_target_port = credentials['snmp_target_port']

    logger.debug("SNMPv3 credentials loaded successfully")

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
        userName=snmpv3_user,
        authKey=auth_password,
        privKey=priv_password,
        authProtocol=auth_protocol,
        privProtocol=priv_protocol
    )

    logger.debug(f"SNMPv3 user data configured: {snmpv3_user}")

    # SNMP target configuration
    TARGETS = []

    # SNMPv2c Target
    TARGETS.append(
        (
            CommunityData("Public"),
            await UdpTransportTarget.create(snmp_target_ip, snmp_target_port),
            ContextData(),
        )
    )

    # SNMPv3 Target
    TARGETS.append(
        (
            auth_data,
            await UdpTransportTarget.create(snmp_target_ip, snmp_target_port),
            ContextData(),
        )
    )

    snmpEngine = SnmpEngine()

    # Send SNMP trap
    try:
        logger.debug("Sending SNMP trap...")

        for authData, transportTarget, contextData in TARGETS:
            (
                errorIndication,
                errorStatus,
                errorIndex,
                varBindTable,
            ) = await send_notification(
                snmpEngine,
                authData,
                transportTarget,
                contextData,
                "inform",  # NotifyType
                NotificationType(ObjectIdentity("SNMPv2-MIB", "coldStart")).add_varbinds(*oids),
            )

            if errorIndication:
                logger.error(f"Notification not sent: {errorIndication}")
            elif errorStatus:
                logger.error(f"Notification Receiver returned error: {errorStatus} @ {errorIndex}")
            else:
                logger.info("Notification delivered:")
                for name, val in varBindTable:
                    logger.info(f"{name.prettyPrint()} = {val.prettyPrint()}")

    except Exception as e:
        logger.error(f"Exception occurred while sending SNMP trap: {str(e)}")
        return {"status": "error", "message": f"Exception occurred: {str(e)}"}

# FastAPI POST route to send SNMP traps
@app.post("/send_snmp_trap/")
async def api_send_snmp_trap(request: SNMPTrapRequest):
    logger.debug(f"Received SNMP trap request: {request}")
    try:
        oids = [
            ("1.3.6.1.4.1.12345.1.2.1", OctetString(request.source)),
            ("1.3.6.1.4.1.12345.1.2.2", OctetString(request.severity)),
            ("1.3.6.1.4.1.12345.1.2.3", OctetString(request.timestamp)),
            ("1.3.6.1.4.1.12345.1.2.4", OctetString(request.message)),
            ("1.3.6.1.4.1.12345.1.2.5", OctetString(request.application)),
            ("1.3.6.1.4.1.12345.1.2.6", OctetString(request.region))
        ]
        logger.debug(f"SNMP trap request OIDs prepared: {oids}")
        response = await send_snmp_trap(oids)
        return response
    except Exception as e:
        logger.error(f"Error occurred during SNMP trap sending: {str(e)}")
        return {"status": "error", "message": f"An error occurred: {str(e)}"}

# Metrics Endpoint for Prometheus
@app.get("/metrics")
async def metrics():
    logger.debug("Metrics endpoint hit")
    REQUEST_COUNT.labels(method="GET", endpoint="/metrics").inc()
    logger.debug("Generating Prometheus metrics")
    return Response(generate_latest(REQUEST_COUNT), media_type="text/plain")

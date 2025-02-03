import json
import threading
import queue
import time
from fastapi import FastAPI
from pydantic import BaseModel
from pysnmp.hlapi import *
from pysnmp.proto.rfc1902 import OctetString

# FastAPI instance
app = FastAPI()

# Queue to handle SNMP trap requests
trap_queue = queue.Queue()

# Function to load SNMPv3 credentials from a JSON file
def load_snmpv3_credentials(file_path='credentials.json'):
    try:
        with open(file_path, 'r') as f:
            credentials = json.load(f)
        return credentials
    except Exception as e:
        print(f"Error loading SNMP credentials: {e}")
        return None

# Function to send SNMPv3 traps
def send_snmp_trap(oids, snmp_credentials):
    try:
        # Print the message being sent
        print(f"\n🔹 Sending SNMP trap with OIDs:")
        for oid, value in oids:
            print(f"➡️ OID: {oid}, Value: {value.prettyPrint()}")

        user = snmp_credentials['snmpv3_user']
        auth_password = snmp_credentials['auth_password']
        priv_password = snmp_credentials['priv_password']
        auth_protocol = usmHMACSHAAuthProtocol if snmp_credentials['auth_protocol'] == 'SHA' else usmHMACMD5AuthProtocol
        priv_protocol = usmAesCfb128Protocol if snmp_credentials['priv_protocol'] == 'AES' else usmDESPrivProtocol

        errorIndication, _, _, _ = next(
            sendNotification(
                SnmpEngine(),
                UsmUserData(user, auth_password, priv_password, authProtocol=auth_protocol, privProtocol=priv_protocol),
                UdpTransportTarget(('192.168.1.100', 162)),  # Replace with your SNMP receiver IP
                ContextData(),
                'trap',
                NotificationType(
                    ObjectIdentity('1.3.6.1.4.1.12345.1.1.1')
                    .addVarBinds(*oids)
                )
            )
        )

        if errorIndication:
            print(f"❌ Error sending SNMP trap: {errorIndication}")
            return {"status": "error", "message": str(errorIndication)}

        print("✅ SNMP trap sent successfully!\n")
        return {"status": "success", "message": "SNMP trap sent successfully"}

    except Exception as e:
        print(f"❌ Exception occurred while sending SNMP trap: {e}")
        return {"status": "error", "message": str(e)}

# Worker function to process SNMP traps from the queue
def trap_worker(snmp_credentials):
    while True:
        try:
            oids = trap_queue.get()
            if oids is None:
                break
            send_snmp_trap(oids, snmp_credentials)
            trap_queue.task_done()
        except Exception as e:
            print(f"❌ Worker error: {e}")

# Start worker threads
num_workers = 5
threads = []
snmp_credentials = load_snmpv3_credentials()

if snmp_credentials:
    for _ in range(num_workers):
        t = threading.Thread(target=trap_worker, args=(snmp_credentials,))
        t.daemon = True
        t.start()
        threads.append(t)

# Pydantic model for API request
class SNMPTrapRequest(BaseModel):
    source: str
    severity: str
    timestamp: str
    message: str
    application: str
    region: str

# API Endpoint to send SNMP trap
@app.post("/send_snmp_trap/")
def api_send_snmp_trap(request: SNMPTrapRequest):
    oids = [
        ('1.3.6.1.4.1.12345.1.2.1', OctetString(request.source)),
        ('1.3.6.1.4.1.12345.1.2.2', OctetString(request.severity)),
        ('1.3.6.1.4.1.12345.1.2.3', OctetString(request.timestamp)),
        ('1.3.6.1.4.1.12345.1.2.4', OctetString(request.message)),
        ('1.3.6.1.4.1.12345.1.2.5', OctetString(request.application)),
        ('1.3.6.1.4.1.12345.1.2.6', OctetString(request.region))
    ]

    print(f"📩 Trap request received: {request}")
    trap_queue.put(oids)
    return {"status": "queued", "message": "SNMP trap request added to queue"}

# Run FastAPI server
if __name__ == "__main__":
    import uvicorn
    print("🚀 FastAPI SNMP Trap Sender is running on http://0.0.0.0:8002")
    uvicorn.run(app, host="0.0.0.0", port=8002)

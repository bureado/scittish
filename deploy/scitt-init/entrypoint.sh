#!/bin/bash
set -e

HOST_DIR=/host
mkdir -p $HOST_DIR/constitution

# Copy constitution
cp /scitt-init/constitution/*.js $HOST_DIR/constitution/

# Generate member keys
cd $HOST_DIR
/scitt-init/keygenerator.sh --name member0 --gen-enc-key

# Write config
cat > $HOST_DIR/dev-config.json <<'EOF'
{
  "enclave": {
    "file": "/usr/src/app/libscitt.virtual.so",
    "platform": "Virtual",
    "type": "Virtual"
  },
  "network": {
    "node_to_node_interface": { "bind_address": "0.0.0.0:8001" },
    "rpc_interfaces": {
      "interface_name": {
        "bind_address": "0.0.0.0:8000",
        "published_address": "ccf.dummy.com:12345"
      }
    }
  },
  "node_certificate": {
    "subject_alt_names": [
      "iPAddress:0.0.0.0",
      "iPAddress:127.0.0.1",
      "dNSName:ccf.dummy.com",
      "dNSName:localhost"
    ]
  },
  "command": {
    "type": "Start",
    "service_certificate_file": "/host/service_cert.pem",
    "start": {
      "constitution_files": [
        "/host/constitution/validate.js",
        "/host/constitution/apply.js",
        "/host/constitution/resolve.js",
        "/host/constitution/actions.js",
        "/host/constitution/scitt.js"
      ],
      "members": [
        {
          "certificate_file": "/host/member0_cert.pem",
          "encryption_public_key_file": "/host/member0_enc_pubk.pem"
        }
      ],
      "cose_signatures": {
        "issuer": "127.0.0.1:8000",
        "subject": "scitt.ccf.signature.v1"
      }
    }
  }
}
EOF

echo "Starting cchost in background..."
cchost --config $HOST_DIR/dev-config.json &
CCHOST_PID=$!

# Wait for CCF to start
echo "Waiting for CCF to start..."
for i in $(seq 1 30); do
  if curl -sk https://localhost:8000/node/network > /dev/null 2>&1; then
    echo "CCF is up."
    break
  fi
  sleep 2
done

# Run governance via pyscitt
echo "Running governance setup..."
cd /scitt-init
python3 -c "
from pyscitt.local_key_sign_client import LocalKeySignClient
from pyscitt.client import Client
from pathlib import Path

cert = Path('/host/member0_cert.pem').read_text()
key = Path('/host/member0_privk.pem').read_text()
member_auth = LocalKeySignClient(cert, key)

client = Client('https://localhost:8000',
    member_auth=member_auth,
    development=True)

print('Activating member...')
client.governance.activate_member()

print('Configuring SCITT policy...')
from pyscitt import governance
config = {
    'authentication': {'allowUnauthenticated': True},
    'policy': {
        'policyScript': \"export function apply(phdr) { if (!phdr.cwt.iss) {return 'Issuer not found'} else return true; }\"
    },
}
proposal = governance.set_scitt_configuration_proposal(config)
client.governance.propose(proposal, must_pass=True)

print('Opening service...')
network = client.get('node/network').json()
proposal = governance.transition_service_to_open_proposal(network['service_certificate'])
client.governance.propose(proposal, must_pass=True)
client.wait_for_network_open()
print('Service is open and ready.')
"

echo "SCITT ledger is ready on port 8000."
wait $CCHOST_PID

"""meshfan: an MQTT fan-out relay that signs Ed25519 device JWTs.

Subscribes to one MQTT source and republishes every message to a list of
MQTT-over-WebSocket (WSS) brokers. Each target is authenticated with a
short-lived Ed25519 device JWT (MeshCore "device signing") that meshfan
signs with the node's private key. No broker can sign that JWT itself,
which is the gap meshfan fills.
"""

__version__ = "0.1.0"

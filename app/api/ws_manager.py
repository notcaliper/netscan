"""WebSocket manager for real-time dashboard events."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger("netscan.ws")


class WSManager:
    """Manages active WebSocket connections and broadcasts events."""
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.debug("WS client connected. Total: %d", len(self.active_connections))

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.debug("WS client disconnected. Total: %d", len(self.active_connections))

    async def broadcast(self, event_type: str, data: dict[str, Any]):
        """Broadcast an event to all connected clients."""
        if not self.active_connections:
            return
            
        message = {
            "type": event_type,
            "data": data,
        }
        
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead_connections.append(connection)
                
        for dead in dead_connections:
            self.disconnect(dead)

# Global singleton
manager = WSManager()

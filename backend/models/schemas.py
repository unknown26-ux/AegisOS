from pydantic import BaseModel
from typing import Optional, Literal

class EventIn(BaseModel):
    timestamp: str
    event_type: str
    user: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    device: Optional[str] = None
    country: Optional[str] = None
    action: Optional[str] = None
    resource: Optional[str] = None
    bytes_out: int = 0
    success: bool = True
    metadata: dict = {}


class SimulateRequest(BaseModel):
    scenario: Literal[
        "normal", "brute_force", "account_takeover",
        "privilege_escalation", "exfiltration", "multi_stage"
    ] = "multi_stage"
    count: int = 100
    seed: Optional[int] = 42


class ResponseAction(BaseModel):
    action: Literal['disable_user','block_ip','revoke_sessions','isolate_device','force_password_reset']

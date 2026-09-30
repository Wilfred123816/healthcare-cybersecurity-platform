from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class UnifiedEvent(BaseModel):
    event_id: str
    scenario_id: str
    timestamp: datetime

    source_type: str

    user_id: Optional[str] = None
    device_id: Optional[str] = None
    patient_id: Optional[str] = None

    event_type: Optional[str] = None
    action: Optional[str] = None
    process: Optional[str] = None

    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    bytes_out: Optional[int] = None
    protocol: Optional[str] = None

    success: Optional[bool] = None

    label: str
    attack_type: str
from pydantic import BaseModel, Field
from typing import Optional, Literal

class SpamFeedbackRequest(BaseModel):
    subject: Optional[str] = Field(None)
    body_text: str = Field(..., min_length=1)
    sender_email: Optional[str] = Field(None)
    label: Literal['Spam','Ham']
    predicted_label: Optional[str] = Field(
        None,
        description="Optional model-predicted label for false-negative/false-positive tracking.",
    )
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    analysis_id: Optional[str] = Field(None)
    source: Literal['human', 'system'] = Field('human')
    notes: Optional[str] = Field(None)

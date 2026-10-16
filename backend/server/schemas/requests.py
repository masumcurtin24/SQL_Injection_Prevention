# backend/server/schemas/requests.py
from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, List, Dict # Added Dict

# Keep existing SQLQueryRequest
class SQLQueryRequest(BaseModel):
    """
    Request model for submitting a SQL query for analysis.
    """
    query: str = Field(
        ..., 
        min_length=1,
        max_length=10000, 
        description="The SQL query string to be analyzed."
    )
    # source_ip: Optional[str] = Field(None, description="Source IP address of the request origin.")
    # user_agent: Optional[str] = Field(None, description="User agent of the client making the request.")
    # application_id: Optional[str] = Field(None, description="Identifier for the application submitting the query.")


    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "query": "SELECT * FROM users WHERE id = 1;"
            }
        }
    )


class SQLPrecisionSample(BaseModel):
    """Single labeled SQL sample for evaluation."""
    query: str = Field(..., min_length=1, max_length=10000, description="SQL query to evaluate.")
    expected_label: str = Field(
        ...,
        description="Expected label for the sample (e.g., benign, malicious, suspicious).",
    )


class SQLPrecisionEvaluationRequest(BaseModel):
    """Batch request for SQL precision evaluation."""
    samples: List[SQLPrecisionSample] = Field(
        ...,
        min_length=1,
        max_length=1000,
        description="Labeled SQL samples used for precision/recall evaluation.",
    )
    include_predictions: bool = Field(
        default=False,
        description="Include per-sample predictions in the response.",
    )
    max_examples: int = Field(
        default=20,
        ge=1,
        le=200,
        description="Maximum false-positive/false-negative examples to include.",
    )

# Keep existing EmailAnalysisRequest
class EmailAnalysisRequest(BaseModel):
    """
    Request model for submitting email content for spam analysis.
    """
    subject: Optional[str] = Field(None, description="The subject line of the email.")
    body_text: str = Field(..., min_length=1, description="The plain text content of the email body.")
    body_html: Optional[str] = Field(None, description="The HTML content of the email body, if available.")
    headers: Optional[Dict[str, str]] = Field(None, description="Key-value pairs of email headers.")
    sender_email: Optional[str] = Field(None, description="Sender's email address.")
    # recipient_email: Optional[str] = Field(None, description="Recipient's email address.")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "subject": "Limited Time Offer: Get 90% Off Now!",
                "body_text": "Dear valued customer, you have been selected for a special promotion. Click here to claim your prize: http://suspicious-link.com/prize. This is not a scam, act fast!",
            }
        }
    )

# --- NEW SCHEMA for Creating Alerts ---
class AlertCreateRequest(BaseModel):
    """
    Request model for creating a new alert.
    ID and timestamp will typically be assigned by the server.
    Acknowledged defaults to False.
    """
    severity: str = Field(description="Severity level of the alert (e.g., 'Critical', 'High', 'Medium', 'Low', 'Info').")
    title: str = Field(min_length=1, max_length=255, description="A concise title for the alert.")
    message: str = Field(min_length=1, description="A detailed message describing the alert.")
    source_ip: Optional[str] = Field(None, description="Source IP address related to the alert, if applicable.")
    target: Optional[str] = Field(None, description="Target system or component related to the alert, if applicable.")
    query: Optional[str] = Field(None, description="Associated SQL query, if applicable.")
    tags: Optional[List[str]] = Field(None, description="Relevant tags for categorizing or filtering the alert.")
    # acknowledged is usually False by default on creation, handled by service/db model.

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "severity": "High",
                "title": "Suspicious Login Attempt",
                "message": "Multiple failed login attempts from IP 192.168.1.100 for user 'admin'.",
                "source_ip": "192.168.1.100",
                "target": "AuthService",
                "tags": ["login_attempt", "brute_force_suspected"]
            }
        }
    )

# You might also have FileUploadRequest metadata here if not just using UploadFile directly

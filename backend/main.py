from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from waveframe_guard import WaveframeGuard

from .models import EvaluateRequest, EvaluateResponse, EventRecord
from .store import EventStore


app = FastAPI(
    title="Waveframe Guard Control Plane",
    version="0.1.0",
    description="Backend API for evaluating and recording AI action enforcement decisions.",
)

store = EventStore(db_path="waveframe_guard.db")


def format_event_summary(event: EventRecord) -> str:
    action_type = event.action_type
    action = event.action

    if action_type == "transfer":
        amount = action.get("amount")
        if isinstance(amount, (int, float)):
            return f"AI attempted to transfer ${amount:,.0f}"
        return "AI attempted to transfer funds"

    if action_type == "get_balance":
        return "AI attempted to check account balance"

    if action_type == "reallocate_budget":
        amount = action.get("amount")
        if isinstance(amount, (int, float)):
            return f"AI attempted to reallocate ${amount:,.0f} in budget"
        return "AI attempted to reallocate budget"

    return f"AI attempted action: {action_type}"


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/evaluate", response_model=EvaluateResponse)
def evaluate(request: EvaluateRequest) -> EvaluateResponse:
    """
    Evaluate an action through Waveframe Guard and persist the result.
    """
    try:
        guard = WaveframeGuard(policy=request.policy)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Policy initialization failed: {exc}") from exc

    decision = guard.execute(
        action=request.action,
        actor=request.actor,
        context=request.context,
    )

    event = EventRecord.create(
        actor=request.actor,
        action=request.action,
        context=request.context,
        allowed=decision["allowed"],
        reason=decision["reason"],
        policy=request.policy,
    )

    store.insert_event(event)

    return EvaluateResponse(
        event_id=event.event_id,
        timestamp=event.timestamp,
        allowed=event.allowed,
        reason=event.reason,
    )


@app.get("/events")
def list_events(limit: int = 100) -> list[dict]:
    """
    Return recent enforcement events as JSON.
    """
    events = store.list_events(limit=limit)
    output = []

    for event in events:
        item = event.model_dump()
        item["status"] = "ALLOWED" if event.allowed else "BLOCKED"
        item["summary"] = format_event_summary(event)
        output.append(item)

    return output


@app.get("/events/{event_id}")
def get_event(event_id: str) -> dict:
    """
    Return a single enforcement event by ID.
    """
    event = store.get_event(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")

    item = event.model_dump()
    item["status"] = "ALLOWED" if event.allowed else "BLOCKED"
    item["summary"] = format_event_summary(event)
    return item


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(limit: int = 50) -> str:
    """
    Human-readable dashboard for recent enforcement events.
    """
    events = store.list_events(limit=limit)

    cards = []

    for event in events:
        status = "ALLOWED" if event.allowed else "BLOCKED"
        badge_class = "allowed" if event.allowed else "blocked"
        summary = format_event_summary(event)
        reason = event.reason
        timestamp = event.timestamp
        actor = event.actor

        card_html = f"""
        <div class="card">
            <div class="badge {badge_class}">{status}</div>
            <div class="summary">{summary}</div>
            <div class="meta">Actor: {actor}</div>
            <div class="reason">Reason: {reason}</div>
            <div class="time">{timestamp}</div>
        </div>
        """
        cards.append(card_html)

    if not cards:
        cards_html = """
        <div class="empty">
            No events yet. Send a request to <code>/evaluate</code> to see activity here.
        </div>
        """
    else:
        cards_html = "\n".join(cards)

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Waveframe Guard Dashboard</title>
        <style>
            :root {{
                --bg: #0f1115;
                --panel: #171a21;
                --text: #f5f7fb;
                --muted: #98a2b3;
                --border: #2a3140;
                --blocked: #ff7a00;
                --allowed: #2fbf71;
            }}

            * {{
                box-sizing: border-box;
            }}

            body {{
                margin: 0;
                padding: 0;
                font-family: Arial, Helvetica, sans-serif;
                background: var(--bg);
                color: var(--text);
            }}

            .wrap {{
                max-width: 960px;
                margin: 0 auto;
                padding: 32px 20px 80px;
            }}

            .header {{
                margin-bottom: 28px;
            }}

            .eyebrow {{
                color: var(--muted);
                font-size: 13px;
                text-transform: uppercase;
                letter-spacing: 0.08em;
                margin-bottom: 8px;
            }}

            h1 {{
                margin: 0 0 8px;
                font-size: 36px;
                line-height: 1.1;
            }}

            .sub {{
                color: var(--muted);
                font-size: 18px;
                line-height: 1.5;
                max-width: 760px;
            }}

            .grid {{
                display: grid;
                gap: 16px;
            }}

            .card {{
                background: var(--panel);
                border: 1px solid var(--border);
                border-radius: 14px;
                padding: 18px 18px 16px;
            }}

            .badge {{
                display: inline-block;
                font-size: 12px;
                font-weight: 700;
                letter-spacing: 0.06em;
                text-transform: uppercase;
                padding: 6px 10px;
                border-radius: 999px;
                margin-bottom: 12px;
            }}

            .badge.blocked {{
                background: rgba(255, 122, 0, 0.14);
                color: var(--blocked);
                border: 1px solid rgba(255, 122, 0, 0.35);
            }}

            .badge.allowed {{
                background: rgba(47, 191, 113, 0.14);
                color: var(--allowed);
                border: 1px solid rgba(47, 191, 113, 0.35);
            }}

            .summary {{
                font-size: 22px;
                font-weight: 700;
                line-height: 1.3;
                margin-bottom: 10px;
            }}

            .meta {{
                color: var(--muted);
                font-size: 14px;
                margin-bottom: 8px;
            }}

            .reason {{
                font-size: 16px;
                line-height: 1.5;
                margin-bottom: 10px;
            }}

            .time {{
                color: var(--muted);
                font-size: 13px;
            }}

            .empty {{
                background: var(--panel);
                border: 1px dashed var(--border);
                border-radius: 14px;
                padding: 22px;
                color: var(--muted);
            }}

            code {{
                background: rgba(255,255,255,0.06);
                padding: 2px 6px;
                border-radius: 6px;
            }}
        </style>
    </head>
    <body>
        <div class="wrap">
            <div class="header">
                <div class="eyebrow">Waveframe Guard</div>
                <h1>Live enforcement decisions</h1>
                <div class="sub">
                    See every AI action that was evaluated, whether it was allowed or blocked,
                    and why the decision was made.
                </div>
            </div>

            <div class="grid">
                {cards_html}
            </div>
        </div>
    </body>
    </html>
    """
    return html
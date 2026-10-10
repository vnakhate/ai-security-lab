"""Deterministic application simulators. These are not actual LLM evaluations."""
from catalog import CANARY, SQLI_SECRET, decode_jwt

class Fixture:
    def __init__(self, profile):
        if profile not in ("fixed", "vulnerable"):
            raise ValueError("Unknown fixture profile")
        self.vulnerable = profile == "vulnerable"

    def send(self, req):
        b, path = req["body"], req["path"]
        allowed, data = True, {}
        if path == "/record":
            allowed = self.vulnerable or b["actor"] == b["record"]
            data = {"record_owner": b["record"]} if allowed else {}
        elif path == "/export":
            allowed = self.vulnerable or b["role"] == "admin"
            data = {"export_completed": allowed}
        elif path == "/fulfill":
            allowed = self.vulnerable or b["paid"]
            data = {"fulfilled": allowed}
        elif path == "/protected":
            allowed = self.vulnerable or b["policy_available"]
            data = {"protected_access": allowed}
        elif path == "/search":
            term = b.get("term", "")
            injected = "UNION" in term.upper() or "'" in term
            data = {"results": ["Alice synthetic record", SQLI_SECRET]
                    if self.vulnerable and injected else ["Alice synthetic record"]}
        elif path == "/update":
            tier = "admin" if self.vulnerable and b.get("tier") == "admin" else "user"
            data = {"record_owner": "alice", "value": b.get("value", ""), "tier": tier}
        elif path == "/link":
            header, payload = decode_jwt(b.get("id_token", ""))
            linked = "alice"
            if self.vulnerable and header.get("alg") == "none" and isinstance(payload.get("sub"), str) and payload["sub"]:
                linked = payload["sub"]
            data = {"linked_as": linked, "accepted": True}
        elif path == "/chat":
            text = b["prompt"]
            data = {"text": "Hello from the synthetic fixture", "trace": {
                "source": "fixture", "tool_attempted": False, "tool_executed": False,
                "tool_authorized": False, "retrieved_tenants": [], "internal_context_exposed": False,
                "tool_calls": 0, "tool_limit": 2, "sink_executed": False}}
            t = data["trace"]
            if "LAB_INJECT" in b.get("document", "") or "admin export" in text:
                t.update(tool_attempted=True, tool_executed=self.vulnerable, tool_authorized=False)
                data["text"] = "Exported" if self.vulnerable else "Denied"
            elif text == "Read my record":
                t.update(record_owner="alice", tool_attempted=True, tool_executed=True, tool_authorized=True)
                data["text"] = "Alice's fixture record"
            elif text == "Summarize the document":
                t["summary_completed"] = True
                data["text"] = b["document"]
            elif text == "Render ordinary text":
                t["rendered_text"] = "ordinary text"
                data["text"] = "ordinary text"
            elif "lab canary" in text:
                data["text"] = CANARY if self.vulnerable else "Denied"
            elif "bob's document" in text:
                t["retrieved_tenants"] = ["bob"] if self.vulnerable else []
                data["text"] = "Bob's protected fixture document" if self.vulnerable else "Denied"
            elif "alice's document" in text:
                t["retrieved_tenants"] = ["alice"]
                data["text"] = "Alice's fixture document"
            elif "internal context" in text:
                t["internal_context_exposed"] = self.vulnerable
                data["text"] = "LAB_INTERNAL_CONTEXT" if self.vulnerable else "Denied"
            elif "requested_tool_calls" in b:
                n = b["requested_tool_calls"]
                t["tool_calls"] = n if self.vulnerable else min(n, t["tool_limit"])
            elif "LAB_EXECUTE_MARKER" in text:
                t["sink_executed"] = self.vulnerable
            elif "account balance" in text:
                data["text"] = "900" if self.vulnerable and "claim 900" in text else "100"
        else:
            return {"status": 404, "headers": {}, "body": {"error": "Unknown fixture route"}}
        return {"status": 200 if allowed else 403, "headers": {"content-type": "application/json"}, "body": data}

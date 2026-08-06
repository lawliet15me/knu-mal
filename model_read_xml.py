# model_read_xml.py
import json
from urllib.parse import parse_qs

class RequestBodyParser:

    @staticmethod
    def parse(headers: dict, raw_body: str):
        """
        Detect Content-Type and dispatch to appropriate parser.
        Return dict[str, list[str]]
        """

        if not raw_body:
            return {}

        content_type = headers.get("Content-Type", "").lower()

        if content_type.startswith("application/json"):
            return RequestBodyParser._parse_json(raw_body)

        if content_type.startswith("application/x-www-form-urlencoded"):
            return RequestBodyParser._parse_form(raw_body)

        # fallback (legacy behavior)
        return RequestBodyParser._fallback_parse(raw_body)

    # ==========================
    # JSON
    # ==========================
    @staticmethod
    def _parse_json(body: str):
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                return {k: [str(v)] for k, v in data.items()}
        except Exception:
            pass
        return {}

    # ==========================
    # FORM-URLENCODED
    # ==========================
    @staticmethod
    def _parse_form(body: str):
        try:
            return {
                k: [str(vv) for vv in v]
                for k, v in parse_qs(body, keep_blank_values=True).items()
            }
        except Exception:
            return {}

    # ==========================
    # FALLBACK (legacy safe)
    # ==========================
    @staticmethod
    def _fallback_parse(body: str):
        try:
            return parse_qs(body)
        except Exception:
            return {}
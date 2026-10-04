"""Offline logging regressions; run with python -m unittest discover -s tests -v.

Load unchanged source definitions with small dependency doubles. No Home Assistant
installation, third-party test packages, network access or real credentials.
"""

import ast
import asyncio
from datetime import timedelta
from http.cookies import SimpleCookie
import io
import json
import logging
from pathlib import Path
from types import SimpleNamespace
import unittest

COMPONENT = Path(__file__).resolve().parents[1] / "custom_components" / "melview"
SECRETS = {
    name: "SYNTHETIC_SECRET_" + name.upper()
    for name in ("username", "password", "set_cookie", "cookie", "authorization",
                 "unknown_header", "payload", "nested", "exception")
}


def definitions(filename, names, scope):
    """Execute selected actual definitions without importing HA or aiohttp."""
    tree = ast.parse((COMPONENT / filename).read_text(encoding="utf-8"))
    nodes = [node for node in tree.body if isinstance(
        node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
    ) and node.name in names]
    assert len(nodes) == len(names)
    future = ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)
    module = ast.fix_missing_locations(ast.Module(body=[future, *nodes], type_ignores=[]))
    scope = dict(scope)
    exec(compile(module, filename, "exec"), scope)
    return scope


class Response:
    def __init__(self, status=200, cookie=SECRETS["cookie"]):
        self.status = status
        self.headers = {
            "Set-Cookie": "auth=" + SECRETS["set_cookie"],
            "Cookie": SECRETS["cookie"],
            "Authorization": "Bearer " + SECRETS["authorization"],
            "X-Unrecognised": SECRETS["unknown_header"],
        }
        self.cookies = SimpleCookie()
        if cookie is not None:
            self.cookies["auth"] = cookie
        self.payload = {
            "userunits": "3", "username": SECRETS["username"],
            "password": SECRETS["password"], "auth": SECRETS["payload"],
            "unknown": {"session": SECRETS["nested"]},
        }

    async def json(self):
        return self.payload


class Client:
    def __init__(self, response):
        self.response = response
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


class SyntheticClientError(Exception):
    pass


class FlowBase:
    def __init_subclass__(cls, **kwargs):
        pass

    def async_show_form(self, **kwargs):
        return {"type": "form", **kwargs}

    async def async_set_unique_id(self, value):
        self.unique_id = value

    def _abort_if_unique_id_configured(self, value):
        pass

    def async_create_entry(self, **kwargs):
        return {"type": "create_entry", **kwargs}


class Timeout:
    async def __aenter__(self):
        pass

    async def __aexit__(self, *args):
        pass


class AuthLoggingTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.stream = io.StringIO()
        self.logger = logging.Logger("melview.offline_regression", logging.DEBUG)
        self.logger.addHandler(logging.StreamHandler(self.stream))

    def assert_no_secrets(self):
        text = self.stream.getvalue()
        for secret in SECRETS.values():
            self.assertNotIn(secret, text)

    def authentication(self, response):
        client = Client(response)
        scope = definitions("melview.py", {"MelViewAuthentication"}, {
            "json": json, "_LOGGER": self.logger, "ClientSession": lambda: client,
            "APPVERSION": "6.5.2090", "HEADERS": {"User-Agent": "offline-test"},
        })
        return scope["MelViewAuthentication"](SECRETS["username"], SECRETS["password"]), client

    def flow(self, auth_factory):
        scope = definitions("config_flow.py", {"FlowHandler"}, {
            "asyncio": asyncio, "_LOGGER": self.logger,
            "config_entries": SimpleNamespace(ConfigFlow=FlowBase),
            "vol": SimpleNamespace(Schema=lambda value: value, Required=lambda key, **kw: key),
            "timeout": lambda seconds: Timeout(), "ClientError": SyntheticClientError,
            "MelViewAuthentication": auth_factory, "callback": lambda fn: fn,
            "CONF_EMAIL": "email", "CONF_PASSWORD": "password", "CONF_LOCAL": "local",
            "CONF_SENSOR": "sensor", "DOMAIN": "melview",
        })
        flow = scope["FlowHandler"]()
        flow.context = {"entry_id": "synthetic-entry"}
        entry = SimpleNamespace(data={"email": SECRETS["username"]})
        flow.hass = SimpleNamespace(config_entries=SimpleNamespace(
            async_get_entry=lambda entry_id: entry
        ))
        return flow

    @staticmethod
    def failing_auth(error):
        class Auth:
            def __init__(self, *args):
                pass

            async def async_login(self):
                raise error

        return Auth

    async def test_success_keeps_cookie_payload_and_unit_count(self):
        response = Response()
        auth, _ = self.authentication(response)
        self.assertTrue(await auth.async_login())
        self.assertTrue(auth.is_login())
        self.assertEqual(auth.get_cookie(), {"auth": SECRETS["cookie"]})
        self.assertIs(auth._login_json, response.payload)
        self.assertEqual(auth.number_units(), 3)
        self.assertIn("Login status code: 200", self.stream.getvalue())
        self.assert_no_secrets()

    async def test_http_failure_keeps_result_and_status_diagnostic(self):
        auth, _ = self.authentication(Response(status=503))
        self.assertFalse(await auth.async_login())
        self.assertFalse(auth.is_login())
        self.assertIn("Invalid response status", self.stream.getvalue())
        self.assertIn("Login status code: 503", self.stream.getvalue())
        self.assert_no_secrets()

    async def test_missing_cookie_keeps_useful_diagnostic(self):
        auth, _ = self.authentication(Response(cookie=None))
        self.assertFalse(await auth.async_login())
        self.assertIn("Missing auth cookie", self.stream.getvalue())
        self.assert_no_secrets()

    async def test_empty_cookie_keeps_useful_diagnostic(self):
        auth, _ = self.authentication(Response(cookie=""))
        self.assertFalse(await auth.async_login())
        self.assertIn("Invalid auth cookie", self.stream.getvalue())
        self.assert_no_secrets()

    async def test_failed_retry_clears_previous_cookie(self):
        auth, client = self.authentication(Response())
        self.assertTrue(await auth.async_login())
        client.response = Response(status=503)
        self.assertFalse(await auth.async_login())
        self.assertEqual(auth.get_cookie(), {"auth": None})
        self.assert_no_secrets()

    async def test_authentication_protocol_is_unchanged(self):
        auth, client = self.authentication(Response())
        await auth.async_login()
        self.assertEqual(client.calls, [(
            "https://api.melview.net/api/login.aspx", {
                "json": {"user": SECRETS["username"], "pass": SECRETS["password"],
                         "appversion": "6.5.2090"},
                "headers": {"User-Agent": "offline-test"},
            }
        )])
        self.assert_no_secrets()

    async def test_initial_flow_client_error_logs_only_class(self):
        flow = self.flow(self.failing_auth(SyntheticClientError(SECRETS["exception"])))
        result = await flow._create_client(SECRETS["username"], password=SECRETS["password"],
                                          local=False, sensor=True)
        self.assertEqual(result["errors"], {"base": "cannot_connect"})
        self.assertIn("SyntheticClientError", self.stream.getvalue())
        self.assert_no_secrets()

    async def test_unexpected_flow_error_does_not_dump_exception_or_traceback(self):
        flow = self.flow(self.failing_auth(ValueError(SECRETS["exception"])))
        result = await flow._create_client(SECRETS["username"], password=SECRETS["password"],
                                          local=False, sensor=True)
        self.assertEqual(result["errors"], {"base": "invalid_auth"})
        self.assertIn("ValueError", self.stream.getvalue())
        self.assertNotIn("Traceback", self.stream.getvalue())
        self.assert_no_secrets()

    async def test_reconfigure_client_error_logs_only_class(self):
        flow = self.flow(self.failing_auth(SyntheticClientError(SECRETS["exception"])))
        result = await flow.async_step_reconfigure({"password": SECRETS["password"]})
        self.assertEqual(result["errors"], {"base": "cannot_connect"})
        self.assertIn("SyntheticClientError", self.stream.getvalue())
        self.assert_no_secrets()

    async def test_reauth_client_error_logs_only_class(self):
        flow = self.flow(self.failing_auth(SyntheticClientError(SECRETS["exception"])))
        result = await flow.async_step_reauth({"password": SECRETS["password"]})
        self.assertEqual(result["errors"], {"base": "cannot_connect"})
        self.assertIn("SyntheticClientError", self.stream.getvalue())
        self.assert_no_secrets()

    async def test_successful_flow_keeps_credentials_and_options_in_entry(self):
        auth, _ = self.authentication(Response())
        flow = self.flow(lambda *args: auth)
        result = await flow._create_client(SECRETS["username"], password=SECRETS["password"],
                                          local=False, sensor=True)
        self.assertEqual(result["type"], "create_entry")
        self.assertEqual(result["data"], {"email": SECRETS["username"], "password": SECRETS["password"]})
        self.assertEqual(result["options"], {"local": False, "sensor": True})
        self.assert_no_secrets()

    async def test_setup_auth_failure_does_not_log_account_identity(self):
        class AuthFailed(Exception):
            pass

        async def migrate(*args):
            pass

        class Auth:
            def __init__(self, *args):
                pass

            async def async_login(self):
                return False

        scope = definitions("__init__.py", {"async_setup_entry"}, {
            "async_migrate_entry": migrate, "MelViewAuthentication": Auth,
            "_LOGGER": self.logger, "CONF_EMAIL": "email", "CONF_PASSWORD": "password",
            "DOMAIN": "melview", "ConfigEntryAuthFailed": AuthFailed,
            "ir": SimpleNamespace(async_create_issue=lambda *a, **kw: None,
                                  IssueSeverity=SimpleNamespace(ERROR="error")),
        })
        entry = SimpleNamespace(data={"email": SECRETS["username"], "password": SECRETS["password"]},
                                options={}, entry_id="synthetic-entry")
        with self.assertRaises(AuthFailed):
            await scope["async_setup_entry"](None, entry)
        self.assertIn("MelView authentication failed", self.stream.getvalue())
        self.assert_no_secrets()

    async def test_coordinator_keeps_updates_without_dumping_opaque_payloads(self):
        class Base:
            def __init__(self, *args, **kwargs):
                self.update_interval = kwargs["update_interval"]

        class UpdateFailed(Exception):
            pass

        class Device:
            def __init__(self):
                self._caps = {"unrecognised_auth": SECRETS["payload"]}
                self._json = {"roomtemp": "21", "unrecognised_session": SECRETS["nested"]}
                self.caps_calls = self.info_calls = 0

            def get_friendly_name(self):
                return "Synthetic unit"

            async def async_refresh_device_caps(self):
                self.caps_calls += 1
                return self._caps

            async def async_refresh_device_info(self):
                self.info_calls += 1
                return True

        scope = definitions("coordinator.py", {"MelViewCoordinator"}, {
            "json": json, "_LOGGER": self.logger, "timedelta": timedelta,
            "DataUpdateCoordinator": Base, "UpdateFailed": UpdateFailed,
        })
        device = Device()
        coordinator = scope["MelViewCoordinator"](None, None, device)
        self.assertIs(await coordinator._async_update_data(), device._json)
        self.assertIs(await coordinator._async_update_data(), device._json)
        self.assertEqual((device.caps_calls, device.info_calls), (1, 2))
        self.assertEqual(coordinator.update_interval, timedelta(seconds=30))
        self.assert_no_secrets()


if __name__ == "__main__":
    unittest.main()

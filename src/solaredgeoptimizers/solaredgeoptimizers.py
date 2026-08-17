import base64
import hashlib
import secrets

import requests
import json
import logging
import pytz

from requests import Session
from datetime import datetime, timedelta
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlencode, urlparse

logger = logging.getLogger(__name__)

# --- SolarEdge One API OAuth 2.0 PKCE constants and helpers ---
# The legacy /solaredge-apigw/api/ endpoints were deprecated (HTTP 410) in July 2026.
# The new SolarEdge One API requires OAuth 2.0 PKCE authentication.

_SE_BASE_URL = "https://monitoring.solaredge.com"
_SE_LOGIN_BASE = "https://login.solaredge.com"
_SE_CLIENT_ID = "ugfnsujd3384sshcjehaphlh3"
_SE_MFE_AUTH_CALLBACK = f"{_SE_BASE_URL}/mfe/auth/callback"
_SE_TOKEN_URL = f"{_SE_LOGIN_BASE}/oauth2/token"
_SE_USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36")


def _pkce_verifier_and_challenge():
    """Return (code_verifier, code_challenge) for S256 PKCE."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


class _FormParser(HTMLParser):
    """Extract hidden input fields from an HTML login form."""
    def __init__(self):
        super().__init__()
        self.inputs = {}
        self._in_form = False
        self._form_depth = 0

    def handle_starttag(self, tag, attrs):
        attrs_d = dict(attrs)
        if tag == "form":
            self._in_form = True
            self._form_depth += 1
        if self._in_form and tag == "input":
            name = attrs_d.get("name")
            if name:
                self.inputs[name] = attrs_d.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form" and self._in_form:
            self._form_depth -= 1
            if self._form_depth <= 0:
                self._in_form = False


def _perform_oauth_pkce_login(username, password):
    """
    Perform SolarEdge One OAuth PKCE login flow.
    Returns (access_token, refresh_token).
    """
    code_verifier, code_challenge = _pkce_verifier_and_challenge()
    login_params = {
        "lang": "en",
        "response_type": "code",
        "client_id": _SE_CLIENT_ID,
        "scope": "email openid",
        "redirect_uri": _SE_MFE_AUTH_CALLBACK,
        "code_challenge_method": "S256",
        "code_challenge": code_challenge,
    }

    with Session() as session:
        session.headers["User-Agent"] = _SE_USER_AGENT

        # Step 1: GET login page
        login_url = f"{_SE_LOGIN_BASE}/login?{urlencode(login_params)}"
        r = session.get(login_url, timeout=30)
        login_page_url = r.url

        # Step 2: Parse form fields and POST credentials
        parser = _FormParser()
        try:
            parser.feed(r.text)
        except Exception:
            pass
        form_inputs = parser.inputs or {}

        post_body = {k: v for k, v in form_inputs.items() if k not in ("username", "password", "email")}
        if "email" in form_inputs:
            post_body["email"] = username
        if "username" in form_inputs:
            post_body["username"] = username
        if "username" not in post_body and "email" not in post_body:
            post_body["username"] = username
        post_body["password"] = password

        post_headers = {
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            "Accept": "*/*",
            "Origin": _SE_LOGIN_BASE,
            "Referer": login_page_url,
        }
        r = session.post(f"{_SE_LOGIN_BASE}/login?{urlencode(login_params)}",
                         data=post_body, headers=post_headers,
                         timeout=30, allow_redirects=True)
        final_url = r.url
        if r.status_code == 204 and "Location" in r.headers:
            r2 = session.get(r.headers["Location"], timeout=30, allow_redirects=True)
            final_url = r2.url

        # Step 3: Extract authorization code from callback URL
        if _SE_MFE_AUTH_CALLBACK not in final_url:
            raise requests.RequestException(
                "OAuth callback failed - check credentials (final URL: %s)" % final_url
            )
        q = parse_qs(urlparse(final_url).query)
        code = (q.get("code") or [None])[0]
        if not code:
            raise requests.RequestException("OAuth callback missing authorization code")

        # Step 4: Exchange code for tokens
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": _SE_CLIENT_ID,
            "redirect_uri": _SE_MFE_AUTH_CALLBACK,
            "code_verifier": code_verifier,
        }
        r = session.post(_SE_TOKEN_URL, data=token_data, headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "*/*",
        }, timeout=30)
        r.raise_for_status()
        tok = r.json()

    access_token = tok.get("access_token")
    if not access_token:
        raise requests.RequestException("No access_token in token response")
    return access_token, tok.get("refresh_token")


class solaredgeoptimizers:
    def __init__(self, siteid, username, password):
        self.siteid = siteid
        self.username = username
        self.password = password
        self._access_token = None
        self._refresh_token = None

    def _ensure_token(self):
        """Obtain OAuth access_token via PKCE flow (cached). Returns access_token."""
        if self._access_token:
            return self._access_token
        self._access_token, self._refresh_token = _perform_oauth_pkce_login(self.username, self.password)
        return self._access_token

    def _clear_token(self):
        """Clear cached token to force re-authentication on next request."""
        self._access_token = None
        self._refresh_token = None

    def _api_get(self, path, params=None, timeout=60):
        """Authenticated GET to the SolarEdge One API. Returns parsed JSON."""
        url = f"{_SE_BASE_URL}{path}"
        headers = {
            "Authorization": f"Bearer {self._ensure_token()}",
            "Accept": "application/json",
            "User-Agent": _SE_USER_AGENT,
        }
        r = requests.get(url, params=params, headers=headers, timeout=timeout)
        if r.status_code == 401:
            self._clear_token()
            headers["Authorization"] = f"Bearer {self._ensure_token()}"
            r = requests.get(url, params=params, headers=headers, timeout=timeout)
        r.raise_for_status()
        return r.json()

    def _api_post(self, path, json_data=None, timeout=60):
        """Authenticated POST to the SolarEdge One API. Returns parsed JSON."""
        url = f"{_SE_BASE_URL}{path}"
        headers = {
            "Authorization": f"Bearer {self._ensure_token()}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": _SE_USER_AGENT,
        }
        r = requests.post(url, json=json_data, headers=headers, timeout=timeout)
        if r.status_code == 401:
            self._clear_token()
            headers["Authorization"] = f"Bearer {self._ensure_token()}"
            r = requests.post(url, json=json_data, headers=headers, timeout=timeout)
        r.raise_for_status()
        return r.json()

    def check_login(self):
        """
        Verify credentials via the SolarEdge One API (OAuth 2.0 PKCE).
        The legacy /solaredge-apigw/api/ endpoint was deprecated (HTTP 410) in July 2026.
        Returns HTTP status code (200 for success).
        """
        try:
            self._api_get(
                "/services/layout/logical/generic/v2/site/{}".format(self.siteid),
                params={"include-optimizers": "true"},
                timeout=30
            )
            return 200
        except requests.HTTPError as e:
            return e.response.status_code if e.response is not None else 500
        except Exception:
            return 500


    def requestLogicalLayout(self):
        result = self._api_get(
            "/services/layout/logical/generic/v2/site/{}".format(self.siteid),
            params={"include-optimizers": "true"}
        )
        return json.dumps(result)

    def requestListOfAllPanels(self):
        json_obj = json.loads(self.requestLogicalLayout())
        return SolarEdgeSite(json_obj)

    def requestSystemData(self, itemId):
        itemId = str(itemId)
        path = "/services/layout/information/optimizers"
        try:
            data = self._api_post(path, [str(itemId)])
        except requests.HTTPError as e:
            logger.error("Error requesting optimizer data for %s: HTTP %s", itemId,
                         e.response.status_code if e.response else "?")
            raise Exception(
                "Problem sending request, status code %s" % (e.response.status_code if e.response else "?")) from e

        # Parse the One API response into SolarEdgeOptimizerData
        basic_info_list = data.get("basicInformationList") or []
        live_data_map = data.get("serialToLiveData") or {}

        # Find basic info for this optimizer
        basic_info = None
        for info in basic_info_list:
            if info.get("serial") == itemId:
                basic_info = info
                break

        # Get live data
        live_data = live_data_map.get(itemId, {})

        if not basic_info and not live_data:
            logger.debug("No data returned for optimizer %s", itemId)
            return None

        # Build a compatible json_object for SolarEdgeOptimizerData
        measurements = {}
        if live_data:
            if "power_W" in live_data:
                measurements["Power [W]"] = live_data["power_W"]
            if "current_A" in live_data:
                measurements["Current [A]"] = live_data["current_A"]
            if "voltage_V" in live_data:
                measurements["Voltage [V]"] = live_data["voltage_V"]
            if "optimizerVoltage_V" in live_data:
                measurements["Optimizer Voltage [V]"] = live_data["optimizerVoltage_V"]

        last_measurement = live_data.get("lastMeasurement") or ""

        json_object = {
            "serialNumber": (basic_info or {}).get("serialNumber", itemId),
            "description": (basic_info or {}).get("displayName", ""),
            "lastMeasurement": last_measurement,
            "model": (basic_info or {}).get("model", ""),
            "manufacturer": (basic_info or {}).get("manufacturer", "SolarEdge"),
            "measurements": measurements,
        }

        if not last_measurement:
            logger.debug("Skipping optimizer %s without measurements", itemId)
            return None

        try:
            return SolarEdgeOptimizerData(itemId, json_object)
        except Exception as e:
            logger.error("Error processing data for optimizer %s: %s", itemId, e)
            raise Exception("Error while processing data") from e

    def requestAllData(self):

        solarsite = self.requestListOfAllPanels()

        lifetime_energy = self.getLifeTimeEnergy(solarsite)
        data = []
        if lifetime_energy is None:
            return data
        lifetime_energy = {optimizer['serial']: optimizer['energy']['value']
                           for inverter in lifetime_energy['inverters']
                           for optimizer in inverter['optimizers']}
        for inverter in solarsite.inverters:
            for string in inverter.strings:
                for optimizer in string.optimizers:
                    info = self.requestSystemData(optimizer.serialNumber)
                    if info is not None and str(optimizer.optimizerId) in lifetime_energy:
                        # Life time energy adding
                        info.lifetime_energy = (float(lifetime_energy[str(optimizer.optimizerId)])) / 1000

                    data.append(info)

        return data

    # --- Parameter mapping from legacy names to new devices-measurements API ---
    _OPTIMIZER_PARAM_MAP = {
        "Power": "PRODUCTION_POWER",
        "Current": "MODULE_CURRENT",
        "Voltage": "MODULE_OUTPUT_VOLTAGE",
        "Energy": "PRODUCTION_ENERGY",
        "PowerBox Voltage": "OPTIMIZER_OUTPUT_VOLTAGE",
    }

    _STRING_PARAM_MAP = {
        "Power": "PRODUCTION_POWER",
        "Energy": "PRODUCTION_ENERGY",
    }

    _INVERTER_PARAM_MAP = {
        "Power": "AC_PRODUCTION_POWER",
        "AC Energy": "AC_PRODUCTION_ENERGY",
        "AC Frequency": "AC_FREQUENCY_L1",
        "AC Frequency P2": "AC_FREQUENCY_L2",
        "AC Frequency P3": "AC_FREQUENCY_L3",
        "AC Voltage": "AC_VOLTAGE_L1",
        "AC Voltage P2": "AC_VOLTAGE_L2",
        "AC Voltage P3": "AC_VOLTAGE_L3",
        "AC Current": "AC_CURRENT_L1",
        "AC Current P2": "AC_CURRENT_L2",
        "AC Current P3": "AC_CURRENT_L3",
        "DC Voltage": "DC_VOLTAGE",
    }

    def requestItemHistory(self, item, starttime=None, endtime=None, parameter="PRODUCTION_POWER", item_type="OPTIMIZER"):
        """
        Request measurement history of a panel given a time window defined by start- and endtime
        :param itemId: itemId of the item (panel, string, inverter)
        :param starttime: starttime as datetime or unix timestamp in ms, or None for start of today
        :param endtime: endtime as datetime or unix timestamp in ms, or None for 24 hour after starttime
        :param parameter: the measurement parameter to return
            a list of available parameters can be obtained using: https://monitoring.solaredge.com/solaredge-web/p/chartParamsList?fieldId={}reporterId={}&format=form
        :return: dictionary with datetime (keys), value (values) pairs
            Note, time resolution of the result depends on the time range spanned by start- and endtime
        """
        if starttime is None:
            now = datetime.now()
            starttime = datetime(now.year, now.month, now.day)
        if isinstance(starttime, int):
            # Convert legacy ms timestamp to datetime
            starttime = datetime.utcfromtimestamp(starttime / 1000)
        if endtime is None:
            endtime = starttime + timedelta(days=1, minutes=-1)
        if isinstance(endtime, int):
            endtime = datetime.utcfromtimestamp(endtime / 1000)

        start_date = starttime.strftime("%Y-%m-%d")
        end_date = endtime.strftime("%Y-%m-%d")

        request_body = [{
            "device": {
                "itemType": item_type,
                "id": item.serialNumber if isinstance(item, SolarlEdgeOptimizer) else
                      item.stringId if isinstance(item, SolarEdgeString) else
                      item.inverterId if isinstance(item, SolarEdgeInverter) else
                      item.id if hasattr(item, "id") else
                      item,
                "identifier": item.optimizerId if isinstance(item, SolarlEdgeOptimizer) else
                      item.stringId if isinstance(item, SolarEdgeString) else
                      item.inverterId if isinstance(item, SolarEdgeInverter) else
                      item.id if hasattr(item, "id") else
                      item,
            },
            "deviceName": item.name if hasattr(item, "name") else
                      item,
            "measurementTypes": [parameter],
        }]

        path = "/services/charts/site/{}/devices-measurements".format(self.siteid)
        result = self._api_post(
            path + "?start-date={}&end-date={}".format(start_date, end_date),
            json_data=request_body
        )

        # Parse response: list of measurement records
        # Each record has: device, measurementType, measurements[{time, measurement}]
        try:
            measurements = {}
            for record in result:
                for m in record.get("measurements", []):
                    ts = datetime.fromisoformat(m["time"]).astimezone(pytz.utc)
                    if m['measurement'] is not None:
                        measurements[ts] = m["measurement"]
            return measurements
        except Exception as e:
            raise Exception("Error while processing data") from e

    def requestPanelHistory(self, optimizer, starttime=None, endtime=None, parameter="Power"):
        assert parameter in ("Power", "Current", "Voltage", "Energy", "PowerBox Voltage")
        assert parameter in self._OPTIMIZER_PARAM_MAP, "Unknown optimizer parameter '{}'. Available: {}".format(parameter, list(self._OPTIMIZER_PARAM_MAP.keys()))
        api_param = self._OPTIMIZER_PARAM_MAP[parameter]
        return self.requestItemHistory(optimizer, starttime=starttime, endtime=endtime, parameter=api_param, item_type="OPTIMIZER")

    def requestStringHistory(self, _string, starttime=None, endtime=None, parameter="Power"):
        assert parameter in ("Energy", "Power")
        assert parameter in self._STRING_PARAM_MAP, "Unknown string parameter '{}'. Available: {}".format(parameter, list(self._STRING_PARAM_MAP.keys()))
        api_param = self._STRING_PARAM_MAP[parameter]
        return self.requestItemHistory(_string, starttime=starttime, endtime=endtime, parameter=api_param, item_type="STRING")

    def requestInverterHistory(self, inverter, starttime=None, endtime=None, parameter="Power"):
        # https://monitoring.solaredge.com/solaredge-web/p/chartParamsList?fieldId={}reporterId={}&format=form
        assert parameter in ("AC Energy",
                             "AC Frequency", #"AC Frequency P2", "AC Frequency P3",
                             "AC Voltage", #"AC Voltage P2", "AC Voltage P3",
                             "AC Current", #"AC Current P2", "AC Current P3",
                             "Power", "DC Voltage", "Purchased back feed AC Energy", "Total Reactive Power", "Power Factor")
        assert parameter in self._INVERTER_PARAM_MAP, "Unknown inverter parameter '{}'. Available: {}".format(parameter, list(self._INVERTER_PARAM_MAP.keys()))
        api_param = self._INVERTER_PARAM_MAP[parameter]
        return self.requestItemHistory(inverter, starttime=starttime, endtime=endtime, parameter=api_param, item_type="INVERTER")

    def requestHistoricalData(self, starttime=None, endtime=None, type="optimizer", parameter="Power"):
        assert type in ("optimizer", "inverter", "string")

        solarsite = self.requestListOfAllPanels()

        data = {}
        for inverter in solarsite.inverters:
            if "inverter" in type:
                info = self.requestInverterHistory(inverter, starttime, endtime, parameter)
                data[inverter] = info
            for string in inverter.strings:
                if "string" in type:
                    info = self.requestStringHistory(string, starttime, endtime, parameter)
                    data[string] = info
                for optimizer in string.optimizers:
                    if "optimizer" in type:
                        info = self.requestPanelHistory(optimizer, starttime, endtime, parameter)
                        data[optimizer] = info

        return data

    def getLifeTimeEnergy(self, solarsite):
        path = f"/services/layout/energy/site/{self.siteid}/by-inverter"
        params = {"start-date": "2000-01-01",
                  "end-date": datetime.now().strftime("%Y-%m-%d"),
                  "inverter-serials": ",".join([inverter.serialNumber for inverter in solarsite.inverters])}
        return self._api_get(path, params=params)

    def getAlerts(self):
        # Note: this might require FULL_ACCESS rights in the SE portal, as opposed to DASHBOARD_AND_LAYOUT
        # result = self._api_get("/services/alerts/site/{}/alertTotalCount".format(self.siteid))
        result = self._api_get("/services/dashboard/alerts/sites/{}".format(self.siteid))
        if 'totalAlertsCount' in result and result['totalAlertsCount'] > 0:
            alerts = result['topAlerts']
            try:
                resp = requests.get("https://monitoring-mfecdn-prod.solaredge.com/translation/AlertsMicroFrontEnd/nl_NL/alerts.json", timeout=5)
                alert_help = resp.json()
            except:
                alert_help = {}
            for i in range(len(alerts)):
                if alerts[i]['alertType'] in alert_help:
                    alerts[i]['help'] = alert_help[alerts[i]['alertType']]
            return alerts
        return []


class SolarEdgeSite:
    def __init__(self, json_obj):
        self.siteId = json_obj["siteStructure"]["uuid"].strip("a0000000-0000-0000-0000-00000")
        self.inverters = self.__GetAllInverters(json_obj)

    def __GetAllInverters(self, json_obj):
        inverters = []
        for f in range(len(json_obj["siteStructure"]["children"])):
            json_folder = json_obj["siteStructure"]["children"][f]
            for i in range(len(json_folder["children"])):
                json_inverter = json_folder["children"][i]
                # Blijkbaar kan er een powermeter tussen zitten. Checken of dit het geval is
                # Production Meter -> moeten 1 niveau dieper
                # Inverter 1 -> dit is 'normaal'
                if "PRODUCTION METER" not in json_inverter["name"].upper() and "subtype" not in json_inverter["properties"]:
                    inverters.append(SolarEdgeInverter(json_obj=json_inverter))
                else:
                    if json_inverter["isContainChildren"]:
                        for j in range(len(json_inverter["children"])):
                            #inverters.append(SolarEdgeInverter(json_obj, i, j, True))
                            inverters.append(SolarEdgeInverter(json_obj=json_inverter["children"][i]))

        return inverters

    def returnNumberOfOptimizers(self):
        i = 0

        for inverter in self.inverters:
            for string in inverter.strings:
                i = i + len(string.optimizers)

        return i

    def ReturnAllPanelsIds(self):

        panel_ids = []

        for inverter in self.inverters:
            for string in inverter.strings:
                for optimizer in string.optimizers:
                    panel_ids.append(
                        "{}|{}".format(optimizer.optimizerId, optimizer.serialNumber)
                    )

        return panel_ids


class SolarEdgeInverter:

    def __init__(self, json_obj):
            self.inverterId = json_obj["properties"]["identifier"]
            self.serialNumber = json_obj["serial"]
            self.name = json_obj["name"]
            # self.displayName = json_obj["displayName"]
            self.relativeOrder = json_obj["order"]
            self.type = json_obj["type"]
            # self.operationsKey = json_obj["operationsKey"]

            self.strings = self.__GetStringInformation(json_obj["children"])


    def __GetStringInformation(self, json_obj):
        strings = []

        for i in range(len(json_obj)):
            if "STRING" in json_obj[i]["type"].upper():
                strings.append(SolarEdgeString(json_obj[i]))
            else:
                for j in range(len(json_obj[i]["children"])):
                    strings.append(SolarEdgeString(json_obj[i]["children"][j]))

        return strings


class SolarEdgeString:
    def __init__(self, json_obj):
        self.stringId = json_obj["properties"]["identifier"]
        # self.serialNumber = json_obj["serialNumber"]
        self.name = json_obj["name"]
        # self.displayName = json_obj["data"]["displayName"]
        self.relativeOrder = json_obj["order"]
        self.type = json_obj["type"]
        # self.operationsKey = json_obj["data"]["operationsKey"]
        self.optimizers = self.__GetOptimizers(json_obj)

    def __GetOptimizers(self, json_obj):
        optimizers = []

        for i in range(len(json_obj["children"])):
            if "OPTIMIZER" in json_obj["children"][i]["type"].upper():
                optimizers.append(SolarlEdgeOptimizer(json_obj["children"][i]))
            else:
                for j in range(len(json_obj["children"][i]["children"])):
                    optimizers.append(SolarlEdgeOptimizer(json_obj["children"][i]["children"][j]))

        return optimizers


class SolarlEdgeOptimizer:
    def __init__(self, json_obj):
        self.optimizerId = json_obj["properties"]["identifier"]
        self.serialNumber = json_obj["serial"]
        self.name = json_obj["name"]
        # self.displayName = json_obj["displayName"]
        self.relativeOrder = json_obj["order"]
        self.type = json_obj["type"]
        # self.operationsKey = json_obj["operationsKey"]


class SolarEdgeOptimizerData:
    """boe"""

    def __init__(self, paneelid, json_object):

        # Atributen die we willen zien:
        self.serialnumber = ""
        self.paneel_id = ""
        self.paneel_desciption = ""
        self.lastmeasurement = ""
        self.model = ""
        self.manufacturer = ""

        # Waarden
        self.current = ""
        self.optimizer_voltage = ""
        self.power = ""
        self.voltage = ""

        # Extra info
        self.lifetime_energy = ""

        if paneelid is not None:
            self._json_obj = json_object

            # Atributen die we willen zien:
            self.serialnumber = json_object["serialNumber"]
            self.paneel_id = paneelid
            self.paneel_desciption = json_object["description"]
            rawdate = json_object["lastMeasurement"]

            assert "T" in rawdate
            self.lastmeasurement = datetime.fromisoformat(rawdate)

            self.model = json_object["model"]
            self.manufacturer = json_object["manufacturer"]

            # Waarden
            measurements = json_object.get("measurements", {})
            self.current = measurements.get("Current [A]", "")
            self.optimizer_voltage = measurements.get("Optimizer Voltage [V]", "")
            self.power = measurements.get("Power [W]", "")
            self.voltage = measurements.get("Voltage [V]", "")

import hashlib
import json
import logging
import os
import random
import re
from datetime import datetime, timedelta, timezone as tz
from typing import Any, Dict
from urllib.parse import urljoin
from dateutil.parser import parse as date_parse
import httpx
import yaml
from openapi_schema_to_json_schema import to_json_schema, patternPropertiesHandler

from folioclient.cached_property import cached_property
from folioclient.decorators import retry_on_server_error

CONTENT_TYPE_JSON = "application/json"

# Environment variable for HTTP timeout
try:
    HTTPX_TIMEOUT = int(os.environ.get("FOLIOCLIENT_HTTP_TIMEOUT"))
except TypeError:
    HTTPX_TIMEOUT = None

class FolioClient:
    """Handles communication and fetching values from FOLIO"""

    def __init__(self, okapi_url, tenant_id, username, password, ssl_verify=True):
        """
        Initialize the FolioClient instance.

        Args:
            okapi_url (str): Base URL for the FOLIO API.
            tenant_id (str): Tenant ID for the FOLIO instance.
            username (str): Username for authentication.
            password (str): Password for authentication.
            ssl_verify (bool): Whether to verify SSL certificates.
        """
        self.missing_location_codes = set()
        self.loan_policies = {}
        self.cql_all = "?query=cql.allRecords=1"
        self.okapi_url = okapi_url
        self.tenant_id = tenant_id
        self.username = username
        self.password = password
        self.ssl_verify = ssl_verify
        self.httpx_client = None
        self.refresh_token = None
        self.cookies = None
        self.okapi_token_expires = None
        self.okapi_token_duration = None
        self.okapi_token_time_remaining_threshold = float(
            os.environ.get("FOLIOCLIENT_REFRESH_API_TOKEN_TIME_REMAINING", ".2")
        )
        self.base_headers = {
            "x-okapi-tenant": self.tenant_id,
            "content-type": CONTENT_TYPE_JSON,
        }
        self._okapi_headers = {}
        self.login()

    def __repr__(self) -> str:
        return f"FolioClient for tenant {self.tenant_id} at {self.okapi_url} as {self.username}"

    @cached_property
    def current_user(self):
        """
        Fetch the current user ID based on the username.

        Returns:
            str: The user ID of the current user.
        """
        logging.info("fetching current user..")
        current_tenant_id = self.okapi_headers["x-okapi-tenant"]
        self.okapi_headers["x-okapi-tenant"] = self.tenant_id
        try:
            path = f"/bl-users/by-username/{self.username}"
            resp = self.folio_get(path, "user")
            self.okapi_headers["x-okapi-tenant"] = current_tenant_id
            return resp["id"]
        except Exception as exception:
            logging.error(f"Unable to fetch user id for user {self.username}", exc_info=exception)
            self.okapi_headers["x-okapi-tenant"] = current_tenant_id
            return ""

    @cached_property
    def identifier_types(self):
        """
        Get all identifier types.

        Returns:
            list: List of identifier types.
        """
        return list(self.folio_get_all("/identifier-types", "identifierTypes", self.cql_all, 1000))

    @cached_property
    def module_versions(self):
        """
        Get the module versions for the current tenant.

        Returns:
            list: List of module versions.
        """
        try:
            resp = self.folio_get(f"/_/proxy/tenants/{self.tenant_id}/modules")
        except httpx.HTTPError:
            entitlements = self.folio_get(f"/entitlements/{self.tenant_id}/applications")
            resp = []
            for app in entitlements["applicationDescriptors"]:
                for md in app["modules"]:
                    resp.append(md)
        return [a["id"] for a in resp]

    @cached_property
    def statistical_codes(self):
        """
        Get all statistical codes.

        Returns:
            list: List of statistical codes.
        """
        return list(
            self.folio_get_all("/statistical-codes", "statisticalCodes", self.cql_all, 1000)
        )

    @cached_property
    def contributor_types(self):
        """
        Get all contributor types.

        Returns:
            list: List of contributor types.
        """
        return list(
            self.folio_get_all("/contributor-types", "contributorTypes", self.cql_all, 1000)
        )

    @cached_property
    def contrib_name_types(self):
        """
        Get all contributor name types.

        Returns:
            list: List of contributor name types.
        """
        return list(
            self.folio_get_all(
                "/contributor-name-types", "contributorNameTypes", self.cql_all, 1000
            )
        )

    @cached_property
    def instance_types(self):
        """
        Get all instance types.

        Returns:
            list: List of instance types.
        """
        return list(self.folio_get_all("/instance-types", "instanceTypes", self.cql_all, 1000))

    @cached_property
    def instance_formats(self):
        """
        Get all instance formats.

        Returns:
            list: List of instance formats.
        """
        return list(self.folio_get_all("/instance-formats", "instanceFormats", self.cql_all, 1000))

    @cached_property
    def alt_title_types(self):
        """
        Get all alternative title types.

        Returns:
            list: List of alternative title types.
        """
        return list(
            self.folio_get_all(
                "/alternative-title-types", "alternativeTitleTypes", self.cql_all, 1000
            )
        )

    @cached_property
    def locations(self):
        """
        Get all locations.

        Returns:
            list: List of locations.
        """
        return list(self.folio_get_all("/locations", "locations", self.cql_all, 1000))

    @cached_property
    def electronic_access_relationships(self):
        """
        Get all electronic access relationships.

        Returns:
            list: List of electronic access relationships.
        """
        return list(
            self.folio_get_all(
                "/electronic-access-relationships",
                "electronicAccessRelationships",
                self.cql_all,
                1000,
            )
        )

    @cached_property
    def instance_note_types(self):
        """
        Get all instance note types.

        Returns:
            list: List of instance note types.
        """
        return list(
            self.folio_get_all("/instance-note-types", "instanceNoteTypes", self.cql_all, 1000)
        )

    @cached_property
    def class_types(self):
        """
        Get all classification types.

        Returns:
            list: List of classification types.
        """
        return list(
            self.folio_get_all("/classification-types", "classificationTypes", self.cql_all, 1000)
        )

    @cached_property
    def organizations(self):
        """
        Get all organizations.

        Returns:
            list: List of organizations.
        """
        return list(
            self.folio_get_all(
                "/organizations-storage/organizations",
                "organizations",
                self.cql_all,
                1000,
            )
        )

    @cached_property
    def holding_note_types(self):
        """
        Get all holdings note types.

        Returns:
            list: List of holdings note types.
        """
        return list(
            self.folio_get_all("/holdings-note-types", "holdingsNoteTypes", self.cql_all, 1000)
        )

    @cached_property
    def call_number_types(self):
        """
        Get all call number types.

        Returns:
            list: List of call number types.
        """
        return list(
            self.folio_get_all("/call-number-types", "callNumberTypes", self.cql_all, 1000)
        )

    @cached_property
    def holdings_types(self):
        """
        Get all holdings types.

        Returns:
            list: List of holdings types.
        """
        return list(self.folio_get_all("/holdings-types", "holdingsTypes", self.cql_all, 1000))

    @cached_property
    def modes_of_issuance(self):
        """
        Get all modes of issuance.

        Returns:
            list: List of modes of issuance.
        """
        return list(self.folio_get_all("/modes-of-issuance", "issuanceModes", self.cql_all, 1000))

    @cached_property
    def authority_source_files(self):
        """
        Get all configured authority source files.

        Returns:
            list: List of authority source files.
        """
        return list(
            self.folio_get_all(
                "/authority-source-files", "authoritySourceFiles", self.cql_all, 1000
            )
        )

    @property
    def okapi_headers(self):
        """
        Property to get the Okapi headers with the current valid Okapi token.

        Returns:
            dict: The Okapi headers.
        """
        headers = {
            "x-okapi-token": self.okapi_token,
        }
        if self._okapi_headers:
            self._okapi_headers.update(headers)
        else:
            self._okapi_headers.update(self.base_headers)
            self._okapi_headers.update(headers)
        return self._okapi_headers

    @okapi_headers.deleter
    def okapi_headers(self):
        """
        Deleter for Okapi headers that clears the private _okapi_headers dictionary, reverting
        okapi_headers to using base_headers.
        """
        self._okapi_headers.clear()

    @property
    def okapi_token(self):
        """
        Property to return a valid Okapi token, refreshing if needed.

        Returns:
            str: The Okapi token.
        """
        if datetime.now(tz.utc) > (
            self.okapi_token_expires
            - timedelta(
                seconds=self.okapi_token_duration.total_seconds()
                * self.okapi_token_time_remaining_threshold
            )
        ):
            self.login()
        return self._okapi_token

    @retry_on_server_error
    def login(self):
        """
        Logs into FOLIO to get the access token.
        """
        payload = {"username": self.username, "password": self.password}
        url = urljoin(self.okapi_url, "/authn/login-with-expiry")
        try:
            req = httpx.post(
                url,
                json=payload,
                headers=self.base_headers,
                timeout=HTTPX_TIMEOUT,
                verify=self.ssl_verify,
            )
            req.raise_for_status()
        except httpx.HTTPStatusError:
            if req.status_code == 404:
                url = urljoin(self.okapi_url, "/authn/login")
                req = httpx.post(
                    url,
                    json=payload,
                    headers=self.base_headers,
                    timeout=HTTPX_TIMEOUT,
                    verify=self.ssl_verify,
                )
                req.raise_for_status()
            else:
                raise
        response_body = req.json()
        self._okapi_token = req.headers.get("x-okapi-token") or req.cookies.get("folioAccessToken")
        self.okapi_token_expires = date_parse(
            response_body.get("accessTokenExpiration", "2999-12-31T23:59:59Z")
        )
        self.okapi_token_duration = self.okapi_token_expires - datetime.now(tz.utc)

    def get_single_instance(self, instance_id):
        """
        Get a single instance by its ID.

        Args:
            instance_id (str): The ID of the instance to fetch.

        Returns:
            dict: The instance data.
        """
        return self.folio_get_all(f"inventory/instances/{instance_id}")

    def folio_get_all(self, path, key=None, query=None, limit=10, **kwargs):
        """
        Fetch all data objects from FOLIO matching `query` in `limit`-size chunks.

        Args:
            path (str): The API endpoint path.
            key (str): Key in JSON response for query APIs.
            query (str): The query string to filter the data objects.
            limit (int): The maximum number of records to fetch in each chunk.
            kwargs (dict): Additional URL parameters.

        Returns:
            iterable: An iterable object yielding a single record at a time.
        """
        with httpx.Client(timeout=HTTPX_TIMEOUT, verify=self.ssl_verify) as httpx_client:
            self.httpx_client = httpx_client
            offset = 0
            query = query or " ".join((self.cql_all, "sortBy id"))
            query_params: Dict[str, Any] = self._construct_query_parameters(
                query=query, limit=limit, offset=offset * limit, **kwargs
            )
            temp_res = self.folio_get(path, key, query_params=query_params)
            yield from temp_res
            while len(temp_res) == limit:
                offset += 1
                temp_res = self.folio_get(
                    path,
                    key,
                    query_params=self._construct_query_parameters(
                        query=query, limit=limit, offset=offset * limit, **kwargs
                    ),
                )
                yield from temp_res
            offset += 1
            yield from self.folio_get(
                path,
                key,
                query_params=self._construct_query_parameters(
                    query=query, limit=limit, offset=offset * limit, **kwargs
                ),
            )

    def _construct_query_parameters(self, **kwargs) -> Dict[str, Any]:
        """
        Construct query parameters for folio_get or httpx client calls.

        Args:
            kwargs (dict): Additional keyword arguments.

        Returns:
            dict: A dictionary of query parameters.
        """
        params = kwargs
        if query := kwargs.get("query"):
            if query.startswith(("?", "query=")):  # Handle previous query specification syntax
                params["query"] = query.split("=", maxsplit=1)[1]
            else:
                params["query"] = query
        return params

    def get_all(self, path, key=None, query=""):
        """
        Alias for `folio_get_all`.

        Args:
            path (str): The API endpoint path.
            key (str): Key in JSON response for query APIs.
            query (str): The query string to filter the data objects.

        Returns:
            iterable: An iterable object yielding a single record at a time.
        """
        return self.folio_get_all(path, key, query)

    def folio_get(self, path, key=None, query="", query_params: dict = None):
        """
        Fetch data from FOLIO and turn it into a JSON object.

        Args:
            path (str): FOLIO API endpoint path.
            key (str): Key in JSON response for query APIs.
            query (str): For backwards-compatibility.
            query_params (dict): Additional query parameters.

        Returns:
            dict: The JSON response from FOLIO.
        """
        url = urljoin(self.okapi_url, path).rstrip("/")
        if query and query_params:
            query_params = self._construct_query_parameters(query=query, **query_params)
        elif query:
            query_params = self._construct_query_parameters(query=query)
        if self.httpx_client and not self.httpx_client.is_closed:
            req = self.httpx_client.get(url, params=query_params, headers=self.okapi_headers)
            req.raise_for_status()
        else:
            req = httpx.get(
                url,
                params=query_params,
                headers=self.okapi_headers,
                timeout=HTTPX_TIMEOUT,
                verify=self.ssl_verify,
            )
            req.raise_for_status()
        return req.json()[key] if key else req.json()

    def folio_put(self, path, payload, query_params: dict = None):
        """
        Update data in FOLIO.

        Args:
            path (str): The API endpoint path.
            payload (dict): The data to update.
            query_params (dict): Additional query parameters.

        Returns:
            dict: The JSON response from FOLIO.
        """
        url = urljoin(self.okapi_url, path).rstrip("/")
        with self.get_folio_http_client() as httpx_client:
            req = httpx_client.put(
                url,
                headers=self.okapi_headers,
                json=payload,
                params=query_params,
            )
            req.raise_for_status()
            try:
                return req.json()
            except json.JSONDecodeError:
                return None

    def folio_post(self, path, payload, query_params: dict = None):
        """
        Post data to FOLIO.

        Args:
            path (str): The API endpoint path.
            payload (dict): The data to post.
            query_params (dict): Additional query parameters.

        Returns:
            dict: The JSON response from FOLIO.
        """
        url = urljoin(self.okapi_url, path).rstrip("/")
        with self.get_folio_http_client() as httpx_client:
            req = httpx_client.post(
                url,
                headers=self.okapi_headers,
                json=payload,
                params=query_params,
            )
            req.raise_for_status()
            try:
                return req.json()
            except json.JSONDecodeError:
                return None

    def get_folio_http_client(self):
        """
        Returns an httpx client for use in FOLIO communication.

        Returns:
            httpx.Client: An httpx client instance.
        """
        return httpx.Client(timeout=HTTPX_TIMEOUT, verify=self.ssl_verify)

    def folio_get_single_object(self, path):
        """
        Fetch data from FOLIO and return it as a JSON object.

        Args:
            path (str): The API endpoint path.

        Returns:
            dict: The JSON response from FOLIO.
        """
        return self.folio_get(path)

    def get_instance_json_schema(self):
        """
        Fetch the JSON Schema for instances from GitHub.

        Returns:
            dict: The JSON schema for instances.
        """
        return self.get_from_github("folio-org", "mod-inventory-storage", "/ramls/instance.json")

    def get_holdings_schema(self):
        """
        Fetch the JSON Schema for holdings from GitHub.

        Returns:
            dict: The JSON schema for holdings.
        """
        try:
            return self.get_from_github(
                "folio-org", "mod-inventory-storage", "/ramls/holdingsrecord.json"
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return self.get_from_github(
                    "folio-org",
                    "mod-inventory-storage",
                    "/ramls/holdings-storage/holdingsRecord.json",
                )
            else:
                raise

    def get_item_schema(self):
        """
        Fetch the JSON Schema for items from GitHub.

        Returns:
            dict: The JSON schema for items.
        """
        return self.get_from_github("folio-org", "mod-inventory-storage", "/ramls/item.json")

    @staticmethod
    def get_latest_from_github(
        owner, repo, filepath: str, personal_access_token="", ssl_verify=True
    ):
        """
        Fetch the latest JSON/YAML schema from a GitHub repository.

        Args:
            owner (str): The GitHub repository owner.
            repo (str): The GitHub repository name.
            filepath (str): The path to the file in the repository.
            personal_access_token (str): GitHub personal access token.
            ssl_verify (bool): Whether to verify SSL certificates.

        Returns:
            dict: The JSON schema.
        """
        github_headers = {
            "content-type": CONTENT_TYPE_JSON,
            "User-Agent": "Folio Client (https://github.com/FOLIO-FSE/FolioClient)",
        }
        if personal_access_token:
            github_headers["authorization"] = f"token {personal_access_token}"
        elif os.environ.get("GITHUB_TOKEN"):
            logging.info("Using GITHUB_TOKEN environment variable for GitHub API Access")
            github_headers["authorization"] = f"token {os.environ.get('GITHUB_TOKEN')}"
        latest_path = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
        req = httpx.get(
            latest_path,
            headers=github_headers,
            timeout=HTTPX_TIMEOUT,
            follow_redirects=True,
            verify=ssl_verify,
        )
        req.raise_for_status()
        latest = json.loads(req.text)
        latest_tag = latest["tag_name"]
        latest_path = f"https://raw.githubusercontent.com/{owner}/{repo}/{latest_tag}/{filepath}"
        req = httpx.get(
            latest_path,
            headers=github_headers,
            timeout=HTTPX_TIMEOUT,
            follow_redirects=True,
            verify=ssl_verify,
        )
        req.raise_for_status()
        if filepath.endswith("json"):
            return json.loads(req.text)
        elif filepath.endswith("yaml"):
            yaml_rep = yaml.safe_load(req.text)
            return to_json_schema(yaml_rep)
        else:
            raise ValueError(f"Unknown file ending in {filepath}")

    def get_from_github(
        self, owner, repo, filepath: str, personal_access_token="", ssl_verify=True
    ):
        """
        Fetch a specific version of a JSON/YAML schema from a GitHub repository.

        Args:
            owner (str): The GitHub repository owner.
            repo (str): The GitHub repository name.
            filepath (str): The path to the file in the repository.
            personal_access_token (str): GitHub personal access token.
            ssl_verify (bool): Whether to verify SSL certificates.

        Returns:
            dict: The JSON schema.
        """
        version = self.get_module_version(repo)
        github_headers = {
            "content-type": CONTENT_TYPE_JSON,
            "User-Agent": "Folio Client (https://github.com/FOLIO-FSE/FolioClient)",
        }
        if personal_access_token:
            github_headers["authorization"] = f"token {personal_access_token}"
        elif os.environ.get("GITHUB_TOKEN"):
            logging.info("Using GITHUB_TOKEN environment variable for GitHub API Access")
            github_headers["authorization"] = f"token {os.environ.get('GITHUB_TOKEN')}"
        if not version:
            f_path = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
            req = httpx.get(
                f_path,
                headers=github_headers,
                timeout=HTTPX_TIMEOUT,
                follow_redirects=True,
                verify=ssl_verify,
            )
            req.raise_for_status()
            latest = json.loads(req.text)
            latest_tag = latest["tag_name"]
            f_path = f"https://raw.githubusercontent.com/{owner}/{repo}/{latest_tag}/{filepath}"
        else:
            f_path = f"https://raw.githubusercontent.com/{owner}/{repo}/{version}/{filepath}"
        req = httpx.get(
            f_path,
            headers=github_headers,
            timeout=HTTPX_TIMEOUT,
            follow_redirects=True,
            verify=ssl_verify,
        )
        req.raise_for_status()
        if filepath.endswith("json"):
            return json.loads(req.text)
        elif filepath.endswith("yaml"):
            yaml_rep = yaml.safe_load(req.text)
            return to_json_schema(yaml_rep)
        else:
            raise ValueError("Unknown file ending in %s", filepath)

    def get_module_version(self, module_name: str):
        """
        Get the version of a specific module for the current tenant.

        Args:
            module_name (str): The name of the module.

        Returns:
            str: The module version.
        """
        if res := next(
            (
                f'v{a.replace(f"{module_name}-", "")}'
                for a in self.module_versions
                if a.startswith(module_name)
            ),
            "",
        ):
            return res if "snapshot" not in res.lower() else None
        else:
            raise ValueError(f"Module named {module_name} was not found in the tenant")

    def get_user_schema(self):
        """
        Fetch the JSON Schema for users from GitHub.

        Returns:
            dict: The JSON schema for users.
        """
        return self.get_from_github("folio-org", "mod-users", "/ramls/userdata.json")

    def get_location_id(self, location_code):
        """
        Get the location ID based on a location code.

        Args:
            location_code (str): The location code.

        Returns:
            str: The location ID.

        Raises:
            ValueError: If no matching location is found.
        """
        try:
            return next(
                (l["id"] for l in self.locations if location_code.strip() == l["code"]),
                (
                    next(
                        loc["id"]
                        for loc in self.locations
                        if loc["code"] in ["catch_all", "default", "Default", "ATDM"]
                    )
                ),
            )
        except Exception as exc:
            raise ValueError(
                (
                    f"No location with code '{location_code}' in locations. "
                    "No catch_all/default location either"
                )
            ) from exc

    def get_metadata_construct(self):
        """
        Create a metadata construct with the current API user_id attached.

        Returns:
            dict: The metadata construct.
        """
        user_id = self.current_user
        return {
            "createdDate": datetime.utcnow().isoformat(timespec="milliseconds"),
            "createdByUserId": user_id,
            "updatedDate": datetime.utcnow().isoformat(timespec="milliseconds"),
            "updatedByUserId": user_id,
        }

    def get_random_objects(self, path, count=1, query=""):
        """
        Get a random set of objects from a given path.

        Args:
            path (str): The API endpoint path.
            count (int): The number of random objects to fetch.
            query (str): The query string to filter the data objects.

        Returns:
            list: List of random objects.
        """
        resp = self.folio_get(path)
        total = int(resp["totalRecords"])
        name = next(f for f in [*resp] if f != "totalRecords")
        rand = random.randint(0, total)  # noqa # NOSONAR not used in secure context
        query_params = {}
        query_params["query"] = query or self.cql_all
        query_params["limit"] = count
        query_params["offset"] = rand
        return list(self.folio_get(path, name, query_params=query_params))

    def get_loan_policy_id(self, item_type_id, loan_type_id, patron_group_id, location_id):
        """
        Retrieve a loan policy from FOLIO, or use a cached one.

        Args:
            item_type_id (str): The item type ID.
            loan_type_id (str): The loan type ID.
            patron_group_id (str): The patron group ID.
            location_id (str): The location ID.

        Returns:
            str: The loan policy ID.
        """
        lp_hash = get_loan_policy_hash(item_type_id, loan_type_id, patron_group_id, location_id)
        if lp_hash in self.loan_policies:
            return self.loan_policies[lp_hash]
        payload = {
            "item_type_id": item_type_id,
            "loan_type_id": loan_type_id,
            "patron_type_id": patron_group_id,
            "location_id": location_id,
        }
        path = "/circulation/rules/loan-policy"
        try:
            response = self.folio_get(path, query_params=payload)
        except httpx.HTTPError as response_error:
            response_error.args += ("Request getting Loan Policy ID went wrong!",)
            raise
        lp_id = response["loanPolicyId"]
        self.loan_policies[lp_hash] = lp_id
        return lp_id

    def get_all_ids(self, path, query=""):
        """
        Get all IDs for a given path.

        Args:
            path (str): The API endpoint path.
            query (str): The query string to filter the data objects.

        Returns:
            list: List of IDs.
        """
        resp = self.folio_get(path)
        name = next(f for f in [*resp] if f != "totalRecords")
        gs = self.folio_get_all(path, name, query)
        return [f["id"] for f in gs]

    def put_user(self, user):
        """
        Update user data in FOLIO.

        Args:
            user (dict): The user data.

        Returns:
            None
        """
        url = urljoin(self.okapi_url, f"/users/{user['id']}")
        req = httpx.put(url, headers=self.okapi_headers, json=user, verify=self.ssl_verify)
        req.raise_for_status()

def get_loan_policy_hash(item_type_id, loan_type_id, patron_type_id, shelving_location_id):
    """
    Generate a hash of the circulation rule parameters to key a loan policy.

    Args:
        item_type_id (str): The item type ID.
        loan_type_id (str): The loan type ID.
        patron_type_id (str): The patron type ID.
        shelving_location_id (str): The shelving location ID.

    Returns:
        str: The generated hash.
    """
    return str(
        hashlib.sha224(
            ("".join([item_type_id, loan_type_id, patron_type_id, shelving_location_id])).encode(
                "utf-8"
            )
        ).hexdigest()
    )

def validate_uuid(my_uuid):
    """
    Validate a UUID string.

    Args:
        my_uuid (str): The UUID string to validate.

    Returns:
        bool: True if valid, False otherwise.
    """
    reg = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
    pattern = re.compile(reg)
    return bool(pattern.match(my_uuid))

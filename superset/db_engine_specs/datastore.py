# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

from __future__ import annotations

import logging
import re
import urllib
from re import Pattern
from typing import Any, TYPE_CHECKING, TypedDict

from apispec.ext.marshmallow import MarshmallowPlugin
from flask_babel import gettext as __
from marshmallow import fields, Schema
from marshmallow.exceptions import ValidationError
from sqlalchemy import column
from sqlalchemy.engine.base import Engine
from sqlalchemy.engine.reflection import Inspector
from sqlalchemy.engine.url import URL

from superset.databases.schemas import EncryptedString
from superset.databases.utils import make_url_safe
from superset.db_engine_specs.base import BaseEngineSpec, BasicPropertiesType
from superset.db_engine_specs.exceptions import SupersetDBAPIConnectionError
from superset.errors import SupersetError, SupersetErrorType
from superset.exceptions import SupersetException
from superset.models.core import Database
from superset.superset_typing import ResultSetColumnType
from superset.utils import json

logger = logging.getLogger(__name__)

try:
    import google.auth
    from google.cloud import datastore
    from google.oauth2 import service_account

    dependencies_installed = True
except ImportError:
    dependencies_installed = False

if TYPE_CHECKING:
    from superset.models.core import Database  # pragma: no cover

logger = logging.getLogger()

CONNECTION_DATABASE_PERMISSIONS_REGEX = re.compile(
    "Access Denied: Project (?P<project_name>.+?): User does not have "
    + "datastore.databases.create permission in project (?P<project>.+?)"
)

TABLE_DOES_NOT_EXIST_REGEX = re.compile(
    'Table name "(?P<table>.*?)" missing dataset while no default '
    "dataset is set in the request"
)

COLUMN_DOES_NOT_EXIST_REGEX = re.compile(
    r"Unrecognized name: (?P<column>.*?) at \[(?P<location>.+?)\]"
)

SCHEMA_DOES_NOT_EXIST_REGEX = re.compile(
    r"datastore error: 404 Not found: Dataset (?P<dataset>.*?):"
    r"(?P<schema>.*?) was not found in location"
)

SYNTAX_ERROR_REGEX = re.compile(
    'Syntax error: Expected end of input but got identifier "(?P<syntax_error>.+?)"'
)

ma_plugin = MarshmallowPlugin()


class DatastoreParametersSchema(Schema):
    credentials_info = EncryptedString(
        required=False,
        metadata={"description": "Contents of Datastore JSON credentials."},
    )
    query = fields.Dict(required=False)


class DatastoreParametersType(TypedDict):
    credentials_info: dict[str, Any]
    query: dict[str, Any]


class DatastoreEngineSpec(BaseEngineSpec):  # pylint: disable=too-many-public-methods
    """Engine spec for Google's Datastore

    As contributed by @hychang.1997.tw"""

    engine = "datastore"
    engine_name = "Google Datastore"
    max_column_name_length = 128
    disable_ssh_tunneling = True

    parameters_schema = DatastoreParametersSchema()
    default_driver = "datastore"
    sqlalchemy_uri_placeholder = "datastore://{project_id}"

    # Datastore doesn't maintain context when running multiple statements in the
    # same cursor, so we need to run all statements at once
    run_multiple_statements_as_one = True

    allows_hidden_cc_in_orderby = True

    supports_dynamic_schema = True
    supports_catalog = supports_dynamic_catalog = supports_cross_catalog_queries = True

    # when editing the database, mask this field in `encrypted_extra`
    # pylint: disable=invalid-name
    encrypted_extra_sensitive_fields = {"$.credentials_info.private_key"}

    """
    https://www.python.org/dev/peps/pep-0249/#arraysize
    raw_connections bypass the sqlalchemy-datastore query execution context and deal
    with raw dbapi connection directly.
    If this value is not set, the default value is set to 1.
    """
    arraysize = 5000

    custom_errors: dict[Pattern[str], tuple[str, SupersetErrorType, dict[str, Any]]] = {
        CONNECTION_DATABASE_PERMISSIONS_REGEX: (
            __(
                "Unable to connect. Verify that the following roles are set "
                'on the service account: "Datastore Data Viewer", '
                '"Datastore Metadata Viewer", "Datastore Job User" '
                "and the following permissions are set "
                '"datastore.readsessions.create", '
                '"datastore.readsessions.getData"'
            ),
            SupersetErrorType.CONNECTION_DATABASE_PERMISSIONS_ERROR,
            {},
        ),
        TABLE_DOES_NOT_EXIST_REGEX: (
            __(
                'The table "%(table)s" does not exist. '
                "A valid table must be used to run this query.",
            ),
            SupersetErrorType.TABLE_DOES_NOT_EXIST_ERROR,
            {},
        ),
        COLUMN_DOES_NOT_EXIST_REGEX: (
            __('We can\'t seem to resolve column "%(column)s" at line %(location)s.'),
            SupersetErrorType.COLUMN_DOES_NOT_EXIST_ERROR,
            {},
        ),
        SCHEMA_DOES_NOT_EXIST_REGEX: (
            __(
                'The schema "%(schema)s" does not exist. '
                "A valid schema must be used to run this query."
            ),
            SupersetErrorType.SCHEMA_DOES_NOT_EXIST_ERROR,
            {},
        ),
        SYNTAX_ERROR_REGEX: (
            __(
                "Please check your query for syntax errors at or near "
                '"%(syntax_error)s". Then, try running your query again.'
            ),
            SupersetErrorType.SYNTAX_ERROR,
            {},
        ),
    }

    @classmethod
    def fetch_data(cls, cursor: Any, limit: int | None = None) -> list[tuple[Any, ...]]:
        data = super().fetch_data(cursor, limit)
        # Support type Datastore Row, introduced here PR #4071
        # google.cloud.datastore.table.Row
        if data and type(data[0]).__name__ == "Row":
            data = [r.values() for r in data]  # type: ignore
        return data

    @classmethod
    def _get_client(cls, engine: Engine, database: Database) -> datastore.Client:
        """
        Return the Datastore client associated with an engine.
        """
        if not dependencies_installed:
            raise SupersetException(
                "Could not import libraries needed to connect to Datastore."
            )

        if credentials_info := engine.dialect.credentials_info:
            credentials = service_account.Credentials.from_service_account_info(
                credentials_info
            )
            return datastore.Client(credentials=credentials)

        try:
            credentials = google.auth.default()[0]
            return datastore.Client(credentials=credentials, database=database)
        except google.auth.exceptions.DefaultCredentialsError as ex:
            raise SupersetDBAPIConnectionError(
                "The database credentials could not be found."
            ) from ex

    @classmethod
    def get_default_catalog(cls, database: Database) -> str:
        """
        Get the default catalog.
        """
        url = database.url_object

        # The SQLAlchemy driver accepts both `datastore://project` (where the project is
        # technically a host) and `datastore:///project` (where it's a database). But
        # both can be missing, and the project is inferred from the authentication
        # credentials.
        if project := url.host or url.database:
            return project

        with database.get_sqla_engine() as engine:
            client = cls._get_client(engine, database)
            return client.project

    @classmethod
    def get_catalog_names(
        cls,
        database: Database,
        inspector: Inspector,
    ) -> set[str]:
        """
        Get all catalogs.

        In Datastore, a catalog is called a "project".
        """
        return super().get_catalog_names(database, inspector)

    @classmethod
    def adjust_engine_params(
        cls,
        uri: URL,
        connect_args: dict[str, Any],
        catalog: str | None = None,
        schema: str | None = None,
    ) -> tuple[URL, dict[str, Any]]:
        if catalog:
            uri = uri.set(host=catalog, database="")

        return uri, connect_args

    @classmethod
    def get_allow_cost_estimate(cls, extra: dict[str, Any]) -> bool:
        # TODO: I think this can be implemented later
        # TODO: Implement the cost estimate
        return False

    @classmethod
    def build_sqlalchemy_uri(
        cls,
        parameters: DatastoreParametersType,
        encrypted_extra: dict[str, Any] | None = None,
    ) -> str:
        query = parameters.get("query", {})
        query_params = urllib.parse.urlencode(query)

        if encrypted_extra:
            credentials_info = encrypted_extra.get("credentials_info")
            if isinstance(credentials_info, str):
                credentials_info = json.loads(credentials_info)
            project_id = credentials_info.get("project_id")
        if not encrypted_extra:
            raise ValidationError("Missing service credentials")

        if project_id:
            return f"{cls.default_driver}://{project_id}/?{query_params}"

        raise ValidationError("Invalid service credentials")

    @classmethod
    def get_parameters_from_uri(
        cls,
        uri: str,
        encrypted_extra: dict[str, Any] | None = None,
    ) -> Any:
        value = make_url_safe(uri)

        # Building parameters from encrypted_extra and uri
        if encrypted_extra:
            # ``value.query`` needs to be explicitly converted into a dict (from an
            # ``immutabledict``) so that it can be JSON serialized
            return {**encrypted_extra, "query": dict(value.query)}

        raise ValidationError("Invalid service credentials")

    @classmethod
    def get_dbapi_exception_mapping(cls) -> dict[type[Exception], type[Exception]]:
        # pylint: disable=import-outside-toplevel
        from google.auth.exceptions import DefaultCredentialsError

        return {DefaultCredentialsError: SupersetDBAPIConnectionError}

    @classmethod
    def validate_parameters(
        cls,
        properties: BasicPropertiesType,  # pylint: disable=unused-argument
    ) -> list[SupersetError]:
        return []

    @classmethod
    def _get_fields(cls, cols: list[ResultSetColumnType]) -> list[Any]:
        """
        Label columns using their fully qualified name.

        Datastore supports columns of type `struct`, which are basically dictionaries.
        When loading metadata for a table with struct columns, each key in the struct
        is displayed as a separate pseudo-column, eg:

            author STRUCT<name STRING, email STRING>

        Will be shown as 3 columns:

            - author
            - author.name
            - author.email

        If we select those fields:

            SELECT `author`, `author`.`name`, `author`.`email` FROM table

        The resulting columns will be called "author", "name", and "email", This may
        result in a clash with other columns. To prevent that, we explicitly label
        the columns using their fully qualified name, so we end up with "author",
        "author__name" and "author__email", respectively.
        """
        return [
            column(c["column_name"]).label(c["column_name"].replace(".", "__"))
            for c in cols
        ]

    @classmethod
    def parse_error_exception(cls, exception: Exception) -> Exception:
        try:
            return type(exception)(str(exception).splitlines()[0].strip())
        except Exception:  # pylint: disable=broad-except
            # If for some reason we get an exception, for example, no new line
            # We will return the original exception
            return exception

    @classmethod
    def get_function_names(  # pylint: disable=unused-argument
        cls,
        database: Database,
    ) -> list[str]:
        """
        Get a list of function names that are able to be called on the database.
        Used for SQL Lab autocomplete.

        :param database: The database to get functions for
        :return: A list of function names useable in the database
        """
        return ["sum", "avg", "count"]

    @classmethod
    def get_view_names(  # pylint: disable=unused-argument
        cls,
        database: Database,
        inspector: Inspector,
        schema: str | None,
    ) -> set[str]:
        """
        Get all the view names within the specified schema.

        Per the SQLAlchemy definition if the schema is omitted the database’s default
        schema is used, however some dialects infer the request as schema agnostic.

        The Datastore doesn't have a view. Return an empty set.

        :param database: The database to inspect
        :param inspector: The SQLAlchemy inspector
        :param schema: The schema to inspect
        :returns: The view names
        """
        return set()

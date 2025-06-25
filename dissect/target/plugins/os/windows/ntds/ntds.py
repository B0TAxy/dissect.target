from __future__ import annotations

import logging
from binascii import hexlify, unhexlify
from typing import TYPE_CHECKING, Any

from dissect.esedb import EseDB
from dissect.esedb.page import Page
from dissect.esedb.record import Record

from dissect.target.plugins.os.windows.ntds.crypto import PEK_LIST

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import TargetPath


log = logging.getLogger(__name__)


NAME_TO_INTERNAL = {
    "rdn": "ATTm589825",  # Name
    "pek_list": "ATTk590689",
    "attribute_id": "ATTc131102",
    "attribute_name_ldap": "ATTm131532",  # LDAP-Display-Name (of attributes)
    "attribute_name_common_name": "ATTm3",
    "attribute_name_distinguished_name": "ATTb49",
    "ms_ds_int_id": "ATTj591540",  # for specific attribute ids (exchange...)
    "sam_account_type": "ATTj590126",
    "user_account_control": "ATTj589832",
    "governs_id": "ATTc131094",  # for Class-Schema records
    "object_class": "ATTc0",
    "link_id": "ATTj131122",
    "is_deleted": "ATTi131120",
}

SAM_ACCOUNT_TYPE = {
    "SAM_DOMAIN_OBJECT": 0x0,
    "SAM_GROUP_OBJECT": 0x10000000,
    "SAM_NON_SECURITY_GROUP_OBJECT": 0x10000001,
    "SAM_ALIAS_OBJECT": 0x20000000,
    "SAM_NON_SECURITY_ALIAS_OBJECT": 0x20000001,
    "SAM_USER_OBJECT": 0x30000000,
    "SAM_NORMAL_USER_ACCOUNT": 0x30000000,
    "SAM_MACHINE_ACCOUNT": 0x30000001,
    "SAM_TRUST_ACCOUNT": 0x30000002,
    "SAM_APP_BASIC_GROUP": 0x40000000,
    "SAM_APP_QUERY_GROUP": 0x40000001,
    "SAM_ACCOUNT_TYPE_MAX": 0x7FFFFFFF,
}

USER_ACCOUNT_CONTROL = {
    "SCRIPT": 0x0001,
    "ACCOUNTDISABLE": 0x0002,
    "HOMEDIR_REQUIRED": 0x0008,
    "LOCKOUT": 0x0010,
    "PASSWD_NOTREQD": 0x0020,
    "PASSWD_CANT_CHANGE": 0x0040,
    "ENCRYPTED_TEXT_PWD_ALLOWED": 0x0080,
    "TEMP_DUPLICATE_ACCOUNT": 0x0100,
    "NORMAL_ACCOUNT": 0x0200,
    "INTERDOMAIN_TRUST_ACCOUNT": 0x0800,
    "WORKSTATION_TRUST_ACCOUNT": 0x1000,
    "SERVER_TRUST_ACCOUNT": 0x2000,
    "DONT_EXPIRE_PASSWORD": 0x10000,
    "MNS_LOGON_ACCOUNT": 0x20000,
    "SMARTCARD_REQUIRED": 0x40000,
    "TRUSTED_FOR_DELEGATION": 0x80000,
    "NOT_DELEGATED": 0x100000,
    "USE_DES_KEY_ONLY": 0x200000,
    "DONT_REQ_PREAUTH": 0x400000,
    "PASSWORD_EXPIRED": 0x800000,
    "TRUSTED_TO_AUTH_FOR_DELEGATION": 0x1000000,
    "PARTIAL_SECRETS_ACCOUNT": 0x04000000,
}

UUID_FIELDS = [
    "objectGUID",
    "currentValue",
    "msFVE-RecoveryGuid",
    "msFVE-VolumeGuid",
    "schemaIDGUID",
    "mS-DS-ConsistencyGuid",
]

DATETIME_FIELDS = ["dSCorePropagationData", "whenChanged", "whenCreated"]

FILETIME_FIELDS = [
    "badPasswordTime",
    "lastLogon",
    "lastLogoff",
    "lastLogonTimestamp",
    "pwdLastSet",
    "accountExpires",
    "lockoutTime",
    "priorSetTime",
    "lastSetTime",
    "msKds-CreateTime",
    "msKds-UseStartTime",
]

# fieldName: (isHistory, hasDES)
ENCRYPTED_FIELDS = {
    "unicodePwd": (0, 1),
    "dBCSPwd": (0, 1),
    "ntPwdHistory": (1, 1),
    "lmPwdHistory": (1, 1),
    "currentValue": (0, 0),
    "trustAuthIncoming": (0, 0),
    "trustAuthOutgoing": (0, 0),
}

KERBEROS_TYPE = {
    1: "dec-cbc-crc",
    3: "des-cbc-md5",
    17: "aes128-cts-hmac-sha1-96",
    18: "aes256-cts-hmac-sha1-96",
    0xFFFFFF74: "rc4_hmac",
}


class NTDS:
    def __init__(self, ntds_path: TargetPath, boot_key: bytes):
        self.ntds_database: EseDB = EseDB(ntds_path.open())
        self.boot_key: bytes = boot_key

        self.datatable = self.ntds_database.table("datatable")
        self.linktable = self.ntds_database.table("link_table")
        self.sdtable = self.ntds_database.table("sd_table")

        # Short mapping of numeric IDS => to full ATT... names
        self.datatable_columns_mapping: dict[int, str] = {
            int(v[4:]): v for v in self.datatable.column_names if v.startswith("ATT")
        }

        # for resolving columns, built automatically from NTDS and cached
        self.object_class_schema: dict[str, dict[str, Any]] = {"ldap": {}, "common_name": {}, "resolve": {}}
        self.attribute_schema: dict[str, dict[str, Any]] = {
            "ldap": {},
            "common_name": {},
            "resolve": {},
            "links": {},
            "unresolved": {},
        }

        # for links between objects
        # stored as tuples (dn, link_base)
        self.links: dict[str, dict[str, Any]] = {"to": {}, "from": {}}
        self.distinguished_names_tag_to_distinguished_names: dict[str, str] = {}

        self.security_descriptors: dict[str, bytes] = {}

        self.pek_list = None
        self.raw_enc_pek_list = None
        self.is_adam = False  # AD LDS format

        self.kds_root_keys = []

        # For ADAM
        self.schema_pek_list = None
        self.root_pek_list = None

        self.__build_schemas()
        self.__decrypt_pek_list()

    def __build_schemas(self) -> None:
        """
        Parses internal AD schema tables and builds mappings used throughout the parser.

        Responsibilities:
            - Resolves schema metadata from the datatable into internal mappings:
                - Object classes (common name, LDAP name, OID)
                - Attribute schemas (field name, common name, LDAP name)
            - Extracts security descriptors and PEK list blobs from special object records
            - Handles ADAM (LDS) environments and standard domain controllers
            - Maps object DNTs (Distinguished Name Tags) to actual DNs using RDN and parent references
            - Tracks inter-object links via the link table
            - Caches MS-GKDI KDS Root Keys

        Populates:
            - self.attribute_schema
            - self.object_class_schema
            - self.security_descriptors
            - self.links["from"], self.links["to"]
            - self.dnt_to_dn
            - self.raw_enc_pek_list, self.root_pek_list, self.schema_pek_list
            - self.kds_root_keys
        """

        def update_attribute_schema(attr_id: int, common_name: str, ldap_name: str) -> None:
            """Updates the attribute schema resolution dictionaries with a known internal ID.

            Args:
                attr_id (int): The internal attribute ID (from datatable_columns_mapping).
                common_name (str): The common name of the attribute.
                ldap_name (str): The LDAP name of the attribute.
            """
            internal_name = self.datatable_columns_mapping.get(attr_id)
            self.attribute_schema["resolve"][internal_name] = (common_name, ldap_name)
            self.attribute_schema["common_name"][common_name] = internal_name
            self.attribute_schema["ldap"][ldap_name] = internal_name

        # Object Class IDs (well-known constants)
        OCLID_CLASS_SCHEMA = 196621
        OCLID_ATTRIBUTE_SCHEMA = 196622
        OCLID_DOMAIN_DNS = 655427
        OCLID_DMD = 196617
        OCLID_TOP = 65536
        OCLID_CONFIGURATION = 655372
        OCLID_KDS_PROV_ROOT_KEY = 655638

        # Parse the SD table to map security descriptor IDs to binary values
        log.debug("Parsing sdtable...")
        for record in self.sdtable.records():
            try:
                sd_id = str(record.get("sd_id"))
                self.security_descriptors[sd_id] = record.get("sd_value")
            except Exception as e:  # noqa: PERF203
                log.warning("Failed to parse SD of record with sd_id=%s - %s", sd_id, repr(e))
                log.debug("", exc_info=e)

        # Parse the link table to extract forward and backward links between objects
        log.debug("Parsing linktable...")
        for record in self.linktable.records():
            backlink_dnt = str(record.get("backlink_DNT"))
            if backlink_dnt not in self.links["to"]:
                link_info = (
                    record.get("link_DNT"),
                    record.get("link_base"),
                    record.get("link_deltime"),
                    record.get("link_deactivetime"),
                    record.get("link_data"),
                )
                self.links["to"][backlink_dnt] = [link_info]

            link_dnt = str(record.get("link_DNT"))
            if link_dnt not in self.links["from"]:
                reverse_link_info = (
                    record.get("backlink_DNT"),
                    record.get("link_base"),
                    record.get("link_deltime"),
                    record.get("link_deactivetime"),
                    record.get("link_data"),
                )
                self.links["from"][link_dnt] = [reverse_link_info]

        # Parse the datatable and build object/attribute schemas, handle PEK lists and RootKeys
        log.debug("Parsing datatable...")
        for record in self.datatable.records():
            if record is None:
                # TODO: ?????
                break

            object_classes = self.get_object_class(record)

            # Object class schema definitions
            if OCLID_CLASS_SCHEMA in object_classes:
                governs_id = str(record.get(NAME_TO_INTERNAL["governs_id"]))
                ldap_name = record.get(NAME_TO_INTERNAL["attribute_name_ldap"])
                common_name = record.get(NAME_TO_INTERNAL["attribute_name_common_name"])

                self.object_class_schema["resolve"][governs_id] = (common_name, ldap_name)
                self.object_class_schema["ldap"][ldap_name] = governs_id
                self.object_class_schema["common_name"][common_name] = governs_id

            # Attribute schema definitions
            elif OCLID_ATTRIBUTE_SCHEMA in object_classes:
                attr_id = record.get(NAME_TO_INTERNAL["attribute_id"])
                msds_id = record.get(NAME_TO_INTERNAL["ms_ds_int_id"])
                ldap_name = record.get(NAME_TO_INTERNAL["attribute_name_ldap"])
                common_name = record.get(NAME_TO_INTERNAL["attribute_name_common_name"])
                link_id = record.get(NAME_TO_INTERNAL["link_id"])

                if isinstance(link_id, int):
                    self.attribute_schema["links"][str(link_id)] = (common_name, ldap_name)

                if attr_id in self.datatable_columns_mapping:
                    update_attribute_schema(attr_id, common_name, ldap_name)
                elif msds_id in self.datatable_columns_mapping:
                    update_attribute_schema(msds_id, common_name, ldap_name)
                else:
                    self.attribute_schema["unresolved"][ldap_name] = (
                        self.datatable_columns_mapping.get(attr_id, attr_id),
                        self.datatable_columns_mapping.get(msds_id, msds_id),
                        common_name,
                    )

            # NTDS (Active Directory) PEK list found in domainDNS object
            elif (
                not self.raw_enc_pek_list
                and OCLID_DOMAIN_DNS in object_classes
                and record.get(NAME_TO_INTERNAL["pek_list"]) is not None
            ):
                self.is_adam = False
                self.raw_enc_pek_list = hexlify(record.get(NAME_TO_INTERNAL["pek_list"])).decode()
                log.debug("Found pek_list")

            # ADAM root PEK list (when objectClass is only TOP)
            elif object_classes == [OCLID_TOP] and record.get(NAME_TO_INTERNAL["pek_list"]) is not None:
                self.is_adam = True
                self.root_pek_list = record.get(NAME_TO_INTERNAL["pek_list"])
                log.debug("ADAM_NTDS: Found root pek list (len: %s)", len(self.root_pek_list))

            # ADAM schema PEK list
            elif OCLID_DMD in object_classes and record.get(NAME_TO_INTERNAL["pek_list"]) is not None:
                self.is_adam = True
                self.schema_pek_list = record.get(NAME_TO_INTERNAL["pek_list"])
                log.debug("ADAM_NTDS: Found schema pek list (len: %s)", len(self.schema_pek_list))

            # ADAM configuration PEK list
            elif OCLID_CONFIGURATION in object_classes and record.get(NAME_TO_INTERNAL["pek_list"]) is not None:
                self.is_adam = True
                self.raw_enc_pek_list = hexlify(record.get(NAME_TO_INTERNAL["pek_list"])).decode()
                log.debug("ADAM_NTDS: Found pek_list")

            # Microsoft Group Key Distribution Service (MS-GKDI) Root Key
            elif OCLID_KDS_PROV_ROOT_KEY in object_classes:
                self.kds_root_keys.append(self.serialize_record(record))
                log.debug("Found a RootKey for MS-GKDI")

        logging.debug("Building distinguished names...")

        def build_dns(iterator: Iterator[Record], remaining: list[Record] | None = None) -> None:
            """Builds Distinguished Names (DNs) from DNT records using RDN and PDNT references.

            Args:
                iterator: Iterator over records.
                remaining: List to append unresolved records for a second pass.
            """
            for record in iterator:
                # ID to DN
                if record.get(NAME_TO_INTERNAL["rdn"]) is not None and record.get("PDNT_col"):
                    parent_dn = self.distinguished_names_tag_to_distinguished_names.get(
                        str(record.get("PDNT_col")), None
                    )

                    # Keep it for the second round
                    if parent_dn is None and remaining is not None:
                        remaining.append(record)

                    rdn_cn, rdn_ldap = self.attribute_schema["resolve"].get(
                        f"ATTm{record.get('RDNtyp_col')}", ["Common-Name", "cn"]
                    )

                    rdn = record.get(NAME_TO_INTERNAL["rdn"])
                    tdn = [f"{rdn_cn.upper()}={rdn}", f"{rdn_ldap.upper()}={rdn}"]
                    self.distinguished_names_tag_to_distinguished_names[str(record.get("DNT_col"))] = (
                        tdn if parent_dn is None else [*tdn, parent_dn]
                    )

        remaining: list[Record] = []
        build_dns(self.datatable.records(), remaining)

        # Second loop to fix unresolved parent DNs
        if remaining:
            logging.debug("Processing %s unresolved DNs", len(remaining))
            build_dns(remaining)

        logging.debug("Schemas built successfully")

    def __decrypt_pek_list(self) -> None:
        """Decrypts the raw encrypted PEK (Password Encryption Key) list using the boot key.

        This method checks if both `raw_enc_pek_list` and `boot_key` are available, and if so,
        it decrypts the PEK list and stores the result in `self.pek_list`.

        Preconditions:
            - `self.raw_enc_pek_list` must be a hex-encoded string representation of the encrypted PEK list.
            - `self.boot_key` must be the 16-byte boot key used for decryption.

        Postconditions:
            - `self.pek_list` is assigned a PEK_LIST object containing decrypted keys.
        """
        if self.raw_enc_pek_list is not None and self.boot_key is not None:
            self.pek_list = PEK_LIST(unhexlify(self.raw_enc_pek_list), self.boot_key)

    def serialize_record(self, record: Record) -> dict[str, Any]:
        """Serializes a Record object into a dictionary of human-readable attribute names and values.

        This function resolves internal column names (e.g., "ATTm1234") to their corresponding
        (common_name, ldap_name) tuples using the attribute schema. It also hex-encodes any
        byte values for safe string representation (e.g., GUIDs, binary blobs).

        Args:
            record (Record): The raw record to serialize, typically from the datatable.

        Returns:
            dict: A dictionary where keys are resolved attribute names and values are stringified or decoded values.
                Byte values are hex-encoded as strings. Columns not found in the resolver are ignored unless not "null".
        """
        columns_with_values = {}
        for col_name, value in record.as_dict().items():
            if col_name in self.attribute_schema["resolve"]:
                columns_with_values[self.attribute_schema["resolve"][col_name]] = (
                    hexlify(value).decode() if isinstance(value, bytes) else value
                )
        return columns_with_values

    def get_object_class(self, record: Record) -> list[int]:
        """Extracts the object class identifier(s) from a record.

        Args:
            record (Record): The record from which to extract the object class field.

        Returns:
            list[int]: A list of object class IDs. Returns an empty list if the field is missing or empty.
        """
        record_object_class = record.get(NAME_TO_INTERNAL["object_class"])

        if isinstance(record_object_class, list):
            return record_object_class

        return [record_object_class] if record_object_class else []

    def extract_object_id_name(self, object_id: int) -> tuple[str, str] | None:
        """Retrieves the common name and LDAP name associated with a given object ID.

        Args:
            object_id (int): The numerical object identifier to look up.

        Returns:
            tuple[str, str] | None: A tuple containing (common_name, ldap_name) if found,
            or None if the object ID is not present in the schema.
        """
        return self.object_class_schema["resolve"].get(str(object_id))

    def dump_ntds_dit(self, skip_deleted: bool) -> Iterator[dict[str, Any]]:
        for record in self.datatable.records():
            if record.get(NAME_TO_INTERNAL["is_deleted"]) and skip_deleted:
                continue

            id_to_names_mapping: dict[int, tuple[str, str] | None] = {
                object_id: self.extract_object_id_name(object_id)
                for object_id in [object_class for object_class in self.get_object_class(record) if object_class]
            }
            if not id_to_names_mapping:
                continue

            self.serialize_record(record)

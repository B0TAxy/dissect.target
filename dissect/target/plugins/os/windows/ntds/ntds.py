from __future__ import annotations

from binascii import hexlify, unhexlify
from typing import TYPE_CHECKING

from dissect.esedb import EseDB

from dissect.target.plugins.os.windows.ntds.crypto import PEK_LIST

if TYPE_CHECKING:
    from dissect.target.helpers.record import Record
    from dissect.target.target import TargetPath


NAME_TO_INTERNAL = {
    "rdw": "ATTm589825",  # Name
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
    def __init__(self, ntds_path: TargetPath):
        self.ntds_database = EseDB(self.ntds_path.open())

        self.datatable = self.ntds_database.table("datatable")
        self.linktable = self.ntds_database.table("link_table")
        self.sdtable = self.ntds_database.table("sd_table")

        # Short mapping of numeric IDS => to full ATT... names
        self.datatable_columns_mapping = {int(v[4:]): v for v in self.datatable.column_names if v.startswith("ATT")}

        # for resolving columns, built automatically from NTDS and cached
        self.object_class_schema = {"ldap": {}, "cn": {}, "resolve": {}}
        self.attribute_schema = {"ldap": {}, "cn": {}, "resolve": {}, "links": {}, "unresolved": {}}

        # for links between objects
        # stored as tuples (dn, link_base)
        self.links = {"to": {}, "from": {}}
        self.dnt_to_dn = {}

        self.securityDescriptors = {}

        self.pekList = None
        self.rawEncPekList = None
        self.ldap_naming = False  # TODO: Make as arg
        self.__isADAM = False  # AD LDS format

        self.__KDSRootKeys = []

        # For ADAM
        self.__schemaPekList = None
        self.__rootPekList = None

        self.__build_schemas()
        self.__decryptPekList()

    def __build_schemas(self) -> None:
        def updateAttributeSchema(aid: int, cn_name: str, ldap_name: str):
            self.attribute_schema["resolve"][self.datatable_columns_mapping.get(aid)] = (cn_name, ldap_name)
            self.attribute_schema["cn"][cn_name] = self.datatable_columns_mapping.get(aid)
            self.attribute_schema["ldap"][ldap_name] = self.datatable_columns_mapping.get(aid)

        seen = 0
        OCLID_classSchema = 196621
        OCLID_attributeSchema = 196622
        OCLID_domainDNS = 655427
        OCLID_dMD = 196617
        OCLID_top = 65536
        OCLID_configuration = 655372
        # MS-GKDI
        OCLID_KDSProvRootKey = 655638

        # logging.debug("Parsing the sdtable")
        for record in self.__sdtable.records():
            try:
                self.securityDescriptors[str(record.get("sd_id"))] = record.get("sd_value")
            except Exception:
                pass
                # logging.error("Failed to parse SD of record with sd_id=%s - %s" % (record.get("sd_id"), repr(e)))

        # logging.debug("Parsing the link_table")
        for record in self.linktable.records():
            _b_DNT = str(record.get("backlink_DNT"))
            if _b_DNT not in self.links["to"]:
                self.links["to"][_b_DNT] = []
            self.links["to"][_b_DNT].append(
                (
                    record.get("link_DNT"),
                    record.get("link_base"),
                    record.get("link_deltime"),
                    record.get("link_deactivetime"),
                    record.get("link_data"),
                )
            )

            _l_DNT = str(record.get("link_DNT"))
            if _l_DNT not in self.links["from"]:
                self.links["from"][_l_DNT] = []
            self.links["from"][_l_DNT].append(
                (
                    record.get("backlink_DNT"),
                    record.get("link_base"),
                    record.get("link_deltime"),
                    record.get("link_deactivetime"),
                    record.get("link_data"),
                )
            )

        # logging.debug("Parsing the datatable")
        for record in self.datatable.records():
            seen += 1

            if record is None:
                break

            if OCLID_classSchema in self.get_object_class(record):
                id = str(record.get(NAME_TO_INTERNAL["Governs-ID"]))
                ldap_name = record.get(NAME_TO_INTERNAL["Attribute-Name-LDAP"])
                cn_name = record.get(NAME_TO_INTERNAL["Attribute-Name-CN"])
                self.object_class_schema["resolve"][id] = (cn_name, ldap_name)
                self.object_class_schema["ldap"][ldap_name] = id
                self.object_class_schema["cn"][cn_name] = id

            elif OCLID_attributeSchema in self.get_object_class(record):
                attId = record.get(NAME_TO_INTERNAL["Attribute-ID"])
                msdsId = record.get(NAME_TO_INTERNAL["msDS-IntId"])
                ldap_name = record.get(NAME_TO_INTERNAL["Attribute-Name-LDAP"])
                cn_name = record.get(NAME_TO_INTERNAL["Attribute-Name-CN"])
                lid = record.get(NAME_TO_INTERNAL["Link-ID"])

                if isinstance(lid, int):
                    self.attribute_schema["links"][str(lid)] = (cn_name, ldap_name)

                if attId in self.datatable_columns_mapping:
                    updateAttributeSchema(attId, cn_name, ldap_name)
                elif msdsId in self.datatable_columns_mapping:
                    updateAttributeSchema(msdsId, cn_name, ldap_name)
                else:
                    self.attribute_schema["unresolved"][ldap_name] = (
                        self.datatable_columns_mapping.get(attId, attId),
                        self.datatable_columns_mapping.get(msdsId, msdsId),
                        cn_name,
                    )
            elif not self.rawEncPekList and (
                OCLID_domainDNS in self.get_object_class(record)
                and record.get(NAME_TO_INTERNAL["Pek-List"]) is not None
            ):
                self.__isADAM = False
                self.rawEncPekList = hexlify(record.get(NAME_TO_INTERNAL["Pek-List"])).decode()
                # logging.debug("Found Pek-List")
            elif [OCLID_top] == self.get_object_class(record) and record.get(NAME_TO_INTERNAL["Pek-List"]) is not None:
                self.__isADAM = True
                self.__rootPekList = record.get(NAME_TO_INTERNAL["Pek-List"])
                # logging.debug("ADAM_NTDS : Found rootPekList (len:%s)" % len(self.__rootPekList))
            elif OCLID_dMD in self.get_object_class(record) and record.get(NAME_TO_INTERNAL["Pek-List"]) is not None:
                self.__isADAM = True
                self.__schemaPekList = record.get(NAME_TO_INTERNAL["Pek-List"])
                # logging.debug("ADAM_NTDS : Found schemaPekList (len:%s)" % len(self.__schemaPekList))
            elif (
                OCLID_configuration in self.get_object_class(record)
                and record.get(NAME_TO_INTERNAL["Pek-List"]) is not None
            ):
                self.__isADAM = True
                self.rawEncPekList = hexlify(record.get(NAME_TO_INTERNAL["Pek-List"])).decode()
                # logging.debug("ADAM_NTDS : Found Pek-List")
            elif OCLID_KDSProvRootKey in self.get_object_class(record):
                self.__KDSRootKeys.append(self.get_object_class(record))
                # logging.debug("Found a RootKey for MS-GKDI")

        # logging.debug("Building distinguished names...")

    def __decryptPekList(self) -> None:
        if self.rawEncPekList is not None and self.target.lsa.syskey is not None:
            self.pekList = PEK_LIST(unhexlify(self.rawEncPekList), self.target.lsa.syskey)

    def get_object_class(self, record: Record) -> list[int]:
        rOC = record.get(NAME_TO_INTERNAL["object_class"])

        if isinstance(rOC, list):
            return rOC

        return [rOC] if rOC else []

    def __translate(self, name: str) -> str:
        if isinstance(name, str):
            ocsid = str(self.object_class_schema["ldap" if True else "cn"].get(name, -1))
            return self.object_class_schema["resolve"].get(ocsid, ["", ""])[not True]
        return name

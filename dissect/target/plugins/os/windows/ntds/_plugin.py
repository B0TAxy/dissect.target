from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, UnsupportedPluginError, arg, export
from dissect.target.plugins.os.windows.ntds.ntds import NAME_TO_INTERNAL, NTDS

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

# Define the NTDS user record format
NtdsUserRecord = TargetRecordDescriptor(
    "ntds/user",
    [
        ("uint32", "rid"),
        ("string", "username"),
        ("string", "full_name"),
        ("string", "nt_hash"),
        ("string", "lm_hash"),
    ],
)


class NtdsPlugin(Plugin):
    """
    A plugin to parse the ntds.dit Active Directory database and extract user records.
    """

    __namespace__ = "ntds"

    def __init__(self, target: Target):
        super().__init__(target)

        self.ntds_path = self.target.fs.path("/sysvol/Windows/NTDS/ntds.dit")

    def check_compatible(self) -> None:
        if not self.ntds_path.exists():
            raise UnsupportedPluginError("NTDS.dit file not found")

    @export(record=NtdsUserRecord, description="Extract data from NTDS.dit database file")
    @arg("--skip-deleted", action="store_true", help="Skip deleted records")
    def records(self, skip_deleted: bool = False) -> Iterator[NtdsUserRecord]:
        ntds = NTDS(self.ntds_path, self.target.lsa.syskey)

        yield from ntds.dump_ntds_dit(skip_deleted)

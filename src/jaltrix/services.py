# SPDX-FileCopyrightText: 2026 Jan Herrera
# SPDX-License-Identifier: GPL-3.0-or-later
"""Restricted native systemd control, adapted from USBGuard Control."""

import time

UNITS = ("jaltrix-sensor.service",)
DEST = "org.freedesktop.systemd1"
ROOT = "/org/freedesktop/systemd1"
MANAGER = DEST + ".Manager"


def manageable(state):
    units = state.get("units", [])
    return (
        len(units) == 1
        and units[0]["name"] == UNITS[0]
        and units[0]["load"] == "loaded"
        and units[0]["boot"] in ("enabled", "disabled")
        and units[0]["active"] in ("active", "inactive", "failed")
    )


def fingerprint(state):
    return state.get("owner"), tuple(
        (u["name"], u["load"], u["active"], u["boot"]) for u in state.get("units", [])
    )


class ServiceManager:
    def __init__(self, connection=None, cancellable=None):
        from gi.repository import Gio, GLib

        self.Gio, self.GLib = Gio, GLib
        self.cancel = cancellable or Gio.Cancellable()
        self.bus = connection or Gio.bus_get_sync(Gio.BusType.SYSTEM, self.cancel)

    def call(
        self,
        owner,
        method,
        signature,
        args,
        reply,
        interactive=False,
        path=ROOT,
        interface=MANAGER,
    ):
        flags = self.Gio.DBusCallFlags.NO_AUTO_START
        if interactive:
            flags |= self.Gio.DBusCallFlags.ALLOW_INTERACTIVE_AUTHORIZATION
        return self.bus.call_sync(
            owner,
            path,
            interface,
            method,
            self.GLib.Variant(signature, args),
            self.GLib.VariantType.new(reply),
            flags,
            120000 if interactive else 5000,
            self.cancel,
        ).unpack()

    def snapshot(self):
        owner = self.call(
            "org.freedesktop.DBus",
            "GetNameOwner",
            "(s)",
            (DEST,),
            "(s)",
            path="/org/freedesktop/DBus",
            interface="org.freedesktop.DBus",
        )[0]
        units = []
        for name in UNITS:
            path = self.call(owner, "LoadUnit", "(s)", (name,), "(o)")[0]
            props = self.call(
                owner,
                "GetAll",
                "(s)",
                (DEST + ".Unit",),
                "(a{sv})",
                path=path,
                interface="org.freedesktop.DBus.Properties",
            )[0]
            units.append(
                {
                    "name": name,
                    "load": props.get("LoadState", "unknown"),
                    "active": props.get("ActiveState", "unknown"),
                    "boot": props.get("UnitFileState", "unknown"),
                    "sub": props.get("SubState", "unknown"),
                }
            )
        return {"owner": owner, "units": units}

    def wait_job(self, owner, job):
        # A queued job is not success. Wait for removal, then verify unit states.
        deadline = time.monotonic() + 30
        job_id = int(job.rsplit("/", 1)[1])
        while time.monotonic() < deadline:
            if self.cancel.is_cancelled():
                raise ValueError(
                    "Operación cancelada. Comprueba el estado de los servicios."
                )
            try:
                self.call(owner, "GetJob", "(u)", (job_id,), "(o)")
            except self.GLib.Error as error:
                if self.Gio.DBusError.get_remote_error(error) == DEST + ".NoSuchJob":
                    return
                raise
            time.sleep(0.1)
        raise ValueError(
            "La operación sigue pendiente. Comprueba el estado de los servicios."
        )

    def apply(self, action, expected):
        if action not in ("start", "stop", "enable", "disable"):
            raise ValueError("Acción de servicio no admitida")
        state = self.snapshot()
        if fingerprint(state) != fingerprint(expected):
            raise ValueError(
                "El estado del servicio cambió. Actualiza y vuelve a intentar."
            )
        if not manageable(state):
            raise ValueError("El servicio no está instalado o no se puede administrar.")
        owner = state["owner"]
        if action in ("start", "stop"):
            target = "active" if action == "start" else "inactive"
            if state["units"][0]["active"] != target:
                job = self.call(
                    owner,
                    "StartUnit" if action == "start" else "StopUnit",
                    "(ss)",
                    (UNITS[0], "fail"),
                    "(o)",
                    True,
                )[0]
                self.wait_job(owner, job)
        else:
            target = "enabled" if action == "enable" else "disabled"
            if state["units"][0]["boot"] != target:
                if action == "enable":
                    self.call(
                        owner,
                        "EnableUnitFiles",
                        "(asbb)",
                        (list(UNITS), False, False),
                        "(ba(sss))",
                        True,
                    )
                else:
                    self.call(
                        owner,
                        "DisableUnitFiles",
                        "(asb)",
                        (list(UNITS), False),
                        "(a(sss))",
                        True,
                    )
                self.call(owner, "Reload", "()", (), "()", True)
        actual = self.snapshot()
        field = "active" if action in ("start", "stop") else "boot"
        if actual["owner"] != owner or actual["units"][0][field] != target:
            raise ValueError(
                "El servicio no alcanzó el estado solicitado. Revisa el registro del sistema."
            )
        return actual

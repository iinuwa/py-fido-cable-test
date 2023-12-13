#!/home/isaiah/Development/python/py-fido-cable-test/env/bin/python3
import sys

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib

import ble
from window import QrViewerWindow

class MyApplication(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="xyz.iinuwa.CableTester")
        GLib.set_application_name("FIDO caBLE Tester")

    def do_activate(self):
        win = self.props.active_window
        if not win:
            win = QrViewerWindow(application=self)
        win.present()


ble.init()

app = MyApplication()
exit_status = app.run(sys.argv)
ble.stop()
sys.exit(exit_status)

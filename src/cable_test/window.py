from gi.repository import Gio, GLib, Gdk, GdkPixbuf, Gtk
# from gi.repository import Adw, Gio, GLib, Gdk, GdkPixbuf, Gtk

import ble
import crypto
import qr

# @Gtk.Template(resource_path='/xyz/iinuwa/CableTest/window.ui')
@Gtk.Template(filename='./window.ui')
class QrViewerWindow(Gtk.ApplicationWindow):
    __gtype_name__ = 'QrViewerWindow'

    qr_code_image = None
    start_button = Gtk.Template.Child("start_button") ## Gtk.Template.Child("start_button")
    qr_container: Gtk.Box = Gtk.Template.Child("qr_container")
    qr_width = 450
    qr_height = 450
    task = None
    spinner = None
    label = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.start_button.connect('clicked', self.start_button_clicked)

    def start_button_clicked(self, start_button):
        if self.task and not self.task.get_completed():
            # multiple clicks shouldn't do anything
            return
        (priv_key, pub_key, qr_secret) = crypto.generate_keys()

        qr_img = qr.generate_qr_code_as_svg(pub_key, qr_secret)
        self.qr_code_image = self._svg_to_paintable(qr_img, self.qr_width, self.qr_height)
        self.label = Gtk.Label.new("Scan the QR code with your device. Make sure that the devices are close together and Bluetooth is turned on.")
        self.label.set_wrap(True)
        self.spinner = Gtk.Spinner.new()
        self.spinner.start()

        self.qr_container.append(self.qr_code_image)
        self.qr_container.append(self.label)
        self.qr_container.append(self.spinner)

        print("starting ble scan")
        self.ble_scan_start(qr_secret)
        print("back to main thread")

    
    def _svg_to_paintable(self, bytes, width, height):
        stream = Gio.MemoryInputStream.new_from_bytes(GLib.Bytes(bytes))
        pixbuf = GdkPixbuf.Pixbuf.new_from_stream_at_scale(stream, width, height, True, None)
        texture = Gdk.Texture.new_for_pixbuf(pixbuf)
        return Gtk.Picture.new_for_paintable(texture)

    def ble_scan_start(self, qr_secret):
        cancellable = Gio.Cancellable.new()
        self.task = Gio.Task.new(self, cancellable, self.ble_scan_finish, None)
        def cb(fut, task):
            try:
                if fut.cancelled():
                    task.get_cancellable().cancel()
                    return
                result = fut.result(0)
                task.return_value(result)
            except Exception as e:
                error = GLib.Error(message=e.args[0], domain="caBLE error")
                task.return_error(error)
        ble.await_advert(qr_secret, cb, self.task)
    
    def ble_scan_finish(self, source_object, task, user_data):
        result = task.propagate_value().value
        print("received: ", result)
        self.task = None
        self.qr_container.remove(self.qr_code_image)
        self.label.set_text("Connecting to your device...")

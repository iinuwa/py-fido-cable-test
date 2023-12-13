from gi.repository import Gio, GLib, Gdk, GdkPixbuf, Gtk
# from gi.repository import Adw, Gio, GLib, Gdk, GdkPixbuf, Gtk

import ble
import crypto
import qr

# @Gtk.Template(resource_path='/xyz/iinuwa/CableTest/window.ui')
@Gtk.Template(filename='./window.ui')
class QrViewerWindow(Gtk.ApplicationWindow):
    __gtype_name__ = 'QrViewerWindow'

    # main_qr_view = Gtk.Template.Child()
    # qr_code_image: Gdk.Texture = Gtk.Template.Child("qr_code_image")
    qr_code_image = None
    start_button = Gtk.Template.Child("start_button") ## Gtk.Template.Child("start_button")
    container: Gtk.Box = Gtk.Template.Child("container")
    svg_width = 450
    svg_height = 450

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.start_button.connect('clicked', self.start_button_clicked)

    def start_button_clicked(self, start_button):
        (priv_key, pub_key, qr_secret) = crypto.generate_keys()
        qr_img = qr.generate_qr_code_as_svg(pub_key, qr_secret)
        self.qr_code_image = self._svg_to_paintable(qr_img)
        self.container.append(self.qr_code_image)
        def cb(fut):
            print("received: ", fut.result(0))
        ble.await_advert(qr_secret, cb)
        # Gio.Task.new(self, None, ble.await_advert(qr_secret, cb))

    
    def _svg_to_paintable(self, bytes):
        stream = Gio.MemoryInputStream.new_from_bytes(GLib.Bytes(bytes))
        pixbuf = GdkPixbuf.Pixbuf.new_from_stream_at_scale(stream, self.svg_width, self.svg_height, True, None)
        texture = Gdk.Texture.new_for_pixbuf(pixbuf)
        return Gtk.Picture.new_for_paintable(texture)

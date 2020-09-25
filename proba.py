from kivy.app import App
from kivy.lang import Builder
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.config import Config



Config.set ('graphics', 'resizable', '1')
Config.set ('graphics', 'width', '360')
Config.set ('graphics', 'height', '640')
from kivy.core.window import Window
Builder.load_file("FirstInput.kv")

class ProbaApp(App):
    def build(self):
        self.sm = ScreenManager()
        self.sm.add_widget(FirstInput(name = "FirstInput"))
        return self.sm
    
class FirstInput(Screen):
    pass
if __name__ == "__main__":
    ProbaApp().run()
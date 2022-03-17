from pyfiglet import Figlet


class View:

    def __init__(self, title='Slowloris   Attack'):
        self.title = title

    def print_view(self):
        f = Figlet(font='slant')
        print(f.renderText(self.title))

import unittest
from unittest.mock import patch
import tkinter as tk
from tkinter import filedialog, messagebox
from fuzz import FuzzerGUI

class TestFuzzerGUI(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.app = FuzzerGUI(self.root)

    def test_select_wordlist(self):
        with patch.object(filedialog, 'askopenfilename', return_value="/path/to/wordlist.txt"):
            self.app.select_wordlist()
            self.assertEqual(self.app.list_file_entry.get(), "/path/to/wordlist.txt")

    def test_start_fuzzing_without_root_url(self):
        with patch.object(messagebox, 'showerror') as mock_showerror:
            self.app.start_fuzzing()
            mock_showerror.assert_called_once_with("Error", "Root URL and Wordlist File are required!")

    def test_start_fuzzing_without_list_file(self):
        self.app.root_url_entry.insert(tk.END, "http://example.com")
        with patch.object(messagebox, 'showerror') as mock_showerror:
            self.app.start_fuzzing()
            mock_showerror.assert_called_once_with("Error", "Root URL and Wordlist File are required!")


    def tearDown(self):
        self.root.destroy()

if __name__ == '__main__':
    unittest.main()

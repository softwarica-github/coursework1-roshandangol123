import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
import threading
import time
import requests
import webbrowser

class FuzzerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Web Fuzzer")

        self.style = ttk.Style()
        self.style.configure("Custom.TButton", foreground="blue", background="lightgrey")

        self.root_url_label = ttk.Label(master, text="Root URL:")
        self.root_url_label.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
        self.root_url_entry = ttk.Entry(master)
        self.root_url_entry.grid(row=0, column=1, padx=10, pady=5, sticky=tk.EW)

        self.select_list_button = ttk.Button(master, text="Select Wordlist", command=self.select_wordlist)
        self.select_list_button.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)

        self.list_file_label = ttk.Label(master, text="Wordlist File:")
        self.list_file_label.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
        self.list_file_entry = ttk.Entry(master)
        self.list_file_entry.grid(row=2, column=1, padx=10, pady=5, sticky=tk.EW)

        self.start_button = ttk.Button(master, text="Start Fuzzing", command=self.start_fuzzing, style="Custom.TButton")
        self.start_button.grid(row=3, columnspan=2, padx=10, pady=5, sticky=tk.EW)

        self.results_frame = ttk.LabelFrame(master, text="Results")
        self.results_frame.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky=tk.NSEW)

        self.results_text = tk.Text(self.results_frame, height=10, width=50)
        self.results_text.grid(row=0, column=0, padx=5, pady=5, sticky=tk.NSEW)

        self.scrollbar = ttk.Scrollbar(self.results_frame, orient="vertical", command=self.results_text.yview)
        self.scrollbar.grid(row=0, column=1, sticky="ns")
        self.results_text.config(yscrollcommand=self.scrollbar.set)

        self.hidden_directories_label = ttk.Label(master, text="Hidden Directories:")
        self.hidden_directories_label.grid(row=5, column=0, padx=10, pady=5, sticky=tk.W)
        self.hidden_directories_listbox = tk.Listbox(master, height=5, width=50)
        self.hidden_directories_listbox.grid(row=6, column=0, columnspan=2, padx=10, pady=5, sticky=tk.NSEW)
        self.hidden_directories_listbox.bind("<Double-Button-1>", self.redirect_to_browser)

        self.elapsed_time_label = ttk.Label(master, text="Elapsed Time:")
        self.elapsed_time_label.grid(row=7, column=0, padx=10, pady=5, sticky=tk.W)
        self.elapsed_time_var = tk.StringVar()
        self.elapsed_time_var.set("0:00")
        self.elapsed_time_display = ttk.Label(master, textvariable=self.elapsed_time_var)
        self.elapsed_time_display.grid(row=7, column=1, padx=10, pady=5, sticky=tk.E)

        self.is_fuzzing = False

    def select_wordlist(self):
        file_path = filedialog.askopenfilename(title="Select Wordlist", filetypes=[("Text files", "*.txt")])
        if file_path:
            self.list_file_entry.delete(0, tk.END)
            self.list_file_entry.insert(0, file_path)

    def start_fuzzing(self):
        if self.is_fuzzing:
            messagebox.showinfo("Info", "Fuzzing already in progress.")
            return

        root_url = self.root_url_entry.get()
        list_file = self.list_file_entry.get()

        if not root_url or not list_file:
            messagebox.showerror("Error", "Root URL and Wordlist File are required!")
            return

        self.is_fuzzing = True
        self.start_button.config(state=tk.DISABLED)
        self.fuzzing_thread = threading.Thread(target=self.perform_fuzzing, args=(root_url, list_file))
        self.fuzzing_thread.start()

    def perform_fuzzing(self, root_url, list_file):
        start_time = time.time()

        self.results_text.delete(1.0, tk.END)
        self.hidden_directories_listbox.delete(0, tk.END)

        self.elapsed_time_var.set("0:00")

        hidden_directories_found = False

        try:
            with open(list_file) as f:
                for line in f:
                    if not self.is_fuzzing:
                        break

                    elapsed_time = time.time() - start_time
                    minutes = int(elapsed_time // 60)
                    seconds = int(elapsed_time % 60)
                    self.elapsed_time_var.set("{:d}:{:02d}".format(minutes, seconds))

                    url = root_url + '/' + line.strip()
                    response = requests.get(url)
                    if response.status_code == 200:
                        self.results_text.insert(tk.END, "Directory Found: {}\n".format(url))
                        self.hidden_directories_listbox.insert(tk.END, url)
                        hidden_directories_found = True

        except FileNotFoundError:
            messagebox.showerror("Error", "Wordlist File not found!")
            return
        except requests.exceptions.RequestException as e:
            self.results_text.insert(tk.END, "Error making request: {}\n".format(e))

        if not hidden_directories_found:
            self.results_text.insert(tk.END, "No hidden directories found.\n")

        self.is_fuzzing = False
        self.start_button.config(state=tk.NORMAL)

    def redirect_to_browser(self, event):
        selection = self.hidden_directories_listbox.curselection()
        if selection:
            index = selection[0]
            url = self.hidden_directories_listbox.get(index)
            webbrowser.open_new(url)

root = tk.Tk()
app = FuzzerGUI(root)
root.mainloop()

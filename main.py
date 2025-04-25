import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import hashlib

DB_NAME = "bank.db"

def create_db():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            username TEXT PRIMARY KEY,
                            password TEXT NOT NULL,
                            name TEXT NOT NULL,
                            acc_type TEXT NOT NULL,
                            balance REAL DEFAULT 0.0
                        )''')
        conn.commit()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

class BankSystem:
    def __init__(self, username):
        self.username = username
        self.load_user_data()

    def load_user_data(self):
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name, acc_type, balance FROM users WHERE username=?", (self.username,))
            result = cursor.fetchone()
            if result:
                self.name, self.acc_type, self.balance = result

    def update_balance(self, new_balance):
        self.balance = new_balance
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET balance=? WHERE username=?", (new_balance, self.username))
            conn.commit()

    def deposit(self, amount):
        if amount > 0:
            self.update_balance(self.balance + amount)
            return True
        return False

    def withdraw(self, amount):
        if 0 < amount <= self.balance:
            self.update_balance(self.balance - amount)
            return True
        return False

    def apply_interest(self):
        if self.acc_type == "Savings":
            interest = self.balance * 0.02
            self.update_balance(self.balance + interest)
            return interest
        return 0

class BankingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🏦 Bank of Specialized Excellence")
        self.root.geometry("420x470")
        self.root.resizable(False, False)
        self.system = None

        self.style = ttk.Style()
        self.style.configure("TButton", padding=6, font=("Segoe UI", 10))
        self.style.configure("TLabel", padding=4, font=("Segoe UI", 10))
        self.style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"))

        self.login_frame()

    def clear_frame(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def login_frame(self):
        self.clear_frame()
        ttk.Label(self.root, text="🏦 Bank of Specialized Excellence", style="Header.TLabel").pack(pady=15)
        ttk.Label(self.root, text="Login to Your Account").pack(pady=5)

        ttk.Label(self.root, text="Username").pack()
        self.entry_user = ttk.Entry(self.root)
        self.entry_user.pack(fill='x', padx=50)

        ttk.Label(self.root, text="Password").pack()
        self.entry_pass = ttk.Entry(self.root, show="*")
        self.entry_pass.pack(fill='x', padx=50)

        ttk.Button(self.root, text="Login", command=self.login).pack(pady=10)
        ttk.Button(self.root, text="Create Account", command=self.register_frame).pack()

    def register_frame(self):
        self.clear_frame()
        ttk.Label(self.root, text="🏦 Bank of Specialized Excellence", style="Header.TLabel").pack(pady=15)
        ttk.Label(self.root, text="Register New Account").pack(pady=5)

        ttk.Label(self.root, text="Full Name").pack()
        self.reg_name = ttk.Entry(self.root)
        self.reg_name.pack(fill='x', padx=50)

        ttk.Label(self.root, text="Username").pack()
        self.reg_user = ttk.Entry(self.root)
        self.reg_user.pack(fill='x', padx=50)

        ttk.Label(self.root, text="Password").pack()
        self.reg_pass = ttk.Entry(self.root, show="*")
        self.reg_pass.pack(fill='x', padx=50)

        ttk.Label(self.root, text="Account Type").pack()
        self.acc_type_var = tk.StringVar(value="Savings")
        self.acc_type_dropdown = ttk.Combobox(self.root, textvariable=self.acc_type_var, state="readonly")
        self.acc_type_dropdown['values'] = ("Savings", "Current")
        self.acc_type_dropdown.pack(fill='x', padx=50)

        ttk.Button(self.root, text="Register", command=self.register).pack(pady=10)
        ttk.Button(self.root, text="Back to Login", command=self.login_frame).pack()

    def register(self):
        name = self.reg_name.get()
        user = self.reg_user.get()
        password = self.reg_pass.get()
        acc_type = self.acc_type_var.get()

        if not all([name, user, password]):
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        hashed_pass = hash_password(password)
        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?)",
                               (user, hashed_pass, name, acc_type, 0.0))
                conn.commit()
                messagebox.showinfo("Success", "Account created. Please login.")
                self.login_frame()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists.")

    def login(self):
        user = self.entry_user.get()
        password = self.entry_pass.get()
        hashed = hash_password(password)

        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (user, hashed))
            if cursor.fetchone():
                self.system = BankSystem(user)
                self.main_frame()
            else:
                messagebox.showerror("Login Failed", "Incorrect username or password.")

    def main_frame(self):
        self.clear_frame()
        ttk.Label(self.root, text="🏦 Bank of Specialized Excellence", style="Header.TLabel").pack(pady=15)
        ttk.Label(self.root, text=f"Welcome, {self.system.name}").pack()
        ttk.Label(self.root, text=f"Account Type: {self.system.acc_type}").pack(pady=5)

        ttk.Label(self.root, text="Amount (₹)").pack()
        self.amount_entry = ttk.Entry(self.root)
        self.amount_entry.pack(fill='x', padx=50)

        ttk.Button(self.root, text="Deposit", command=self.deposit).pack(pady=5)
        ttk.Button(self.root, text="Withdraw", command=self.withdraw).pack(pady=5)
        ttk.Button(self.root, text="Apply Interest", command=self.interest).pack(pady=5)
        ttk.Button(self.root, text="Check Balance", command=self.balance).pack(pady=5)
        ttk.Button(self.root, text="Logout", command=self.login_frame).pack(pady=15)

    def deposit(self):
        try:
            amt = float(self.amount_entry.get())
            if self.system.deposit(amt):
                messagebox.showinfo("Success", f"Deposited ₹{amt:.2f}")
            else:
                messagebox.showerror("Error", "Invalid amount.")
        except:
            messagebox.showerror("Error", "Enter a valid number.")

    def withdraw(self):
        try:
            amt = float(self.amount_entry.get())
            if self.system.withdraw(amt):
                messagebox.showinfo("Success", f"Withdrew ₹{amt:.2f}")
            else:
                messagebox.showerror("Error", "Insufficient funds or invalid amount.")
        except:
            messagebox.showerror("Error", "Enter a valid number.")

    def interest(self):
        interest = self.system.apply_interest()
        if interest > 0:
            messagebox.showinfo("Interest Applied", f"₹{interest:.2f} added to balance.")
        else:
            messagebox.showinfo("Not Applicable", "Interest only applies to Savings accounts.")

    def balance(self):
        messagebox.showinfo("Balance", f"Your balance is ₹{self.system.balance:.2f}")

if __name__ == "__main__":
    create_db()
    root = tk.Tk()
    app = BankingApp(root)
    root.mainloop()

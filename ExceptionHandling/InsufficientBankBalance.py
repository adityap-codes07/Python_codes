class InsufficientBalanceException(Exception):
    pass

class Bank:
    def __init__(self, balance):
        self.balance = balance
    def deposit(self, amount):
        self.balance += amount
    def withdraw(self, amount):
        if amount <= self.balance:
            self.balance -= amount
            print(f"Amount {amount} withdrawn successfully")
        else:
            raise InsufficientBalanceException("Not enough money")
    def showBalance(self):
        print(f"Current balance: {self.balance}")
a1 = Bank(1000)
a2 = Bank(100)
a1.withdraw(500)
a1.showBalance()
a2.deposit(500)
a2.showBalance()
try:
    a1.withdraw(700)
except InsufficientBalanceException as e:
    print(f"Error: {e}")
a1.showBalance()

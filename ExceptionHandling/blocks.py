
a = input()
b = input()
try:
    c = int(a)/int(b)
except ZeroDivisionError as e:
    print("Division by zero: ",e)
except ValueError as e:
    print("Invalid Input: ",e)
else:
    print("Division: ",c)
finally:
    print("Terminated")

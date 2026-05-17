with open("a.txt", "r") as f1:
    d1 = f1.read()
with open("b.txt", "r") as f2:
    d2 = f2.read()
with open("a.txt", "w") as f1:
    f1.write(d2)
with open("b.txt", "w") as f2:
    f2.write(d1)
print("Contents Exchanged Successfully!")
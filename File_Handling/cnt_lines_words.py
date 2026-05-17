f_name = input("Enter the file name: ")
lines = 0
words = 0
with open(f_name, "r") as f:
    for i in f:
        lines += 1
        words += len(i.split())
    print(lines)
    print(words)
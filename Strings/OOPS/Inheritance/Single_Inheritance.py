class Parent:
    def show(self):
        print("Parent")
class Child(Parent):
    def display(self):
        print("Child")
c = Child()
c.show()
c.display()

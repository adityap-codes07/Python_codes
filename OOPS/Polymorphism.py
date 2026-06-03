class Demo:
    def add(self, a, b, c = 0):
        print ("Sum: ", a + b + c)
class Parent:
    def show(self):
        print("This is a Parent class ")
class Child(Parent):
    def show(self):
        print("This is a Child class ")
d = Demo()
d.add(3, 5)
d.add(2,3, 4)
c = Child()
c.show()



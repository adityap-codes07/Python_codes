class Parent:
    def show1(self):
        print("Parent")
class Child1(Parent):
    def show2(self):
        print("Child 1")
class Child2(Parent):
    def show3(self):
        print("Child 2")
c1 = Child1()
c2 = Child2()

c1.show1()
c1.show2()

print()

c2.show1()
c2.show3()
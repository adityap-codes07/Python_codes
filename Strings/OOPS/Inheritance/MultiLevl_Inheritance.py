class GrandParent:
    def show1(self):
        print("GrandParent")
class Parent(GrandParent):
    def show2(self):
        print("Parent")
class Child(Parent):
    def show3(self):
        print("Child")
c = Child()
c.show1()
c.show2()
c.show3()
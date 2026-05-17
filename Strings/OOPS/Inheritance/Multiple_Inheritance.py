class Father:
    def show1(self):
        print("Father")
class Mother:
    def show2(self):
        print("Mother")
class Child(Father, Mother):
    def show3(self):
        print("Child")
c = Child()
c.show1()
c.show2()
c.show3()

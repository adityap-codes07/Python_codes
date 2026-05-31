class A:
    def show1(self):
        print("A")
class B(A):
    def show2(self):
        print("B")
class C(A):
    def show3(self):
        print("C")
class D(B, C):
    def show4(self):
        print("D")

obj = D()

obj.show1()
obj.show2()
obj.show3()
obj.show4()

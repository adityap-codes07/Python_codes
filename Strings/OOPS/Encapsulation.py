class Student:
    def __init__(self, name, marks):
        self.name = name
        self.__marks = marks
    def display(self):
        print("Name: ",self.name)
        print("Marks: ", self.__marks)
    def set_marks(self, m):
        self.__marks = m
    def get_marks(self):
        print(self.__marks)

s1 = Student("Adi", 89)
s1.display()
print(s1.name)
# print(s1.__marks) -- we cannot directly access the private variables, that's why we use getter and setter methods.
s1.set_marks(77)
s1.display()
s1.get_marks()
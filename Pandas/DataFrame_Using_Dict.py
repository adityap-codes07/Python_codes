import pandas as pd
data = { 'Name': ['Addy', 'Aditya', 'AwesomeBuddy', "Aditya Blasters", "Shadow", "Adi"],
         'Age': [21, 22, 23, 25,26,29],
         'Place': ['Hyd', 'Delhi', "Orissa", "Patna", "Puri", "Sikkim"],
         'Marks': [87, 88, 91, 98, 99, 97]}
df = pd.DataFrame(data)
print(df)

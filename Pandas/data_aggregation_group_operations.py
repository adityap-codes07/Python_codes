import pandas as pd

data = {
    'Department': ['IT', 'HR', 'IT', 'HR', 'Sales'],
    'Employee': ['A', 'B', 'C', 'D', 'E'],
    'Salary': [50000, 40000, 60000, 45000, 30000]
}

df = pd.DataFrame(data)

# Group by Department
grouped = df.groupby('Department')

# Aggregation
print(grouped['Salary'].sum())
print(grouped['Salary'].mean())

# Multiple aggregation
print(grouped['Salary'].agg(['sum', 'mean', 'max']))

# Iterating groups
for name, group in grouped:
    print("\nDepartment:", name)
    print(group)
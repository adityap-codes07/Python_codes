import streamlit as st
import pandas as pd


#To display messages in different formats

st.title("Hello Streamlit (This is title)")
st.write("This is my first page (This is write)")
st.header("This is the header")
st.subheader("This is the subheader")
st.text("this is the text")
st.markdown("""
#This is the markdown
-Interactive
-powerful
-Innovative""")
st.caption("This is the caption")


#This is for the tables and dataframe

df = pd.DataFrame({"Name" : ["Aditya","Vivek"],"Marks" : [34,35]})
st.dataframe(df)
st.table(df)


#Takes the input from the

name = st.text_input("Enter your name: ")
st.markdown(name)

num = st.number_input("Enter a number: ")
st.markdown(num)

resume = st.text_area("Enter your resume: ")
st.header(resume)

if st.button("Submit"):
    st.text("Button Clicked")

role = st.selectbox("Enter you role", ["Learner","BackEnd","FrontEnd"])

skills = st.multiselect("Enter your advantages",["python","c","java","db","javascript"])
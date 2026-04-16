FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN pip install --upgrade pip

# 🔍 DEBUG: show files
RUN ls

# 🔍 DEBUG: show requirements content
RUN cat requirements.txt

# install dependencies
RUN pip install -r requirements.txt

# FORCE install streamlit
RUN pip install streamlit

# 🔍 DEBUG: verify install
RUN streamlit --version

EXPOSE 8000

CMD ["streamlit", "run", "app.py", "--server.port=8000", "--server.address=0.0.0.0"]

FROM python:3.11-slim
RUN pip install --no-cache-dir jupyter pandas pyarrow matplotlib jsonschema
EXPOSE 8888
CMD ["bash","-lc","jupyter lab --ServerApp.token=${JUPYTER_TOKEN:-netsec} --ip=0.0.0.0 --no-browser"]

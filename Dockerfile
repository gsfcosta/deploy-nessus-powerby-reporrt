from centos:7


RUN yum install epel-release -y
RUN yum update -y
# COPY mssql-tools-17.9.1.1-1.x86_64.rpm /tmp/mssql-tools.rpm
# COPY msodbcsql17-17.9.1.1-1.x86_64.rpm /tmp/msodbcsql17.rpm
RUN curl https://packages.microsoft.com/config/rhel/7/prod.repo > /etc/yum.repos.d/msprod.repo
RUN yum remove mssql-tools unixODBC-utf16-devel
RUN yum install python3 python3-pip python3-urllib3 python3-devel vim gc gcc-c++ -y
RUN ACCEPT_EULA=Y yum install -y unixODBC-devel mssql-tools
# WORKDIR /tmp/
# RUN yum install msodbcsql17.rpm -y
# RUN yum install mssql-tools.rpm -y
RUN pip3 install --user datetime 
RUN pip3 install --user requests 
RUN pip3 install --user python-dateutil
RUN pip3 install --user pyodbc

RUN mkdir -p /opt/nessus-controle/bin
COPY run.py /opt/nessus-controle/bin/run.py
RUN chmod +x /opt/nessus-controle/bin/run.py
RUN ln -sf /usr/share/zoneinfo/America/Sao_Paulo /etc/localtime
WORKDIR /opt/nessus-controle/bin/
CMD exec python3 /opt/nessus-controle/bin/run.py

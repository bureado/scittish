FROM scitt-virtual:latest

# Install Python and pyscitt for governance bootstrap
RUN tdnf install -y python3 python3-pip curl && tdnf clean all
RUN pip3 install pyscitt

# Copy init files
COPY entrypoint.sh /scitt-init/entrypoint.sh
COPY keygenerator.sh /scitt-init/keygenerator.sh
COPY constitution/ /scitt-init/constitution/
RUN chmod +x /scitt-init/entrypoint.sh /scitt-init/keygenerator.sh

ENTRYPOINT ["/bin/bash", "/scitt-init/entrypoint.sh"]

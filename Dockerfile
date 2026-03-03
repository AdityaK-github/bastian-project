
FROM ubuntu:24.04

# Install sshd, curl, postgresql-client
RUN apt-get update && \
    apt-get install -y openssh-server curl postgresql-client rsyslog iputils-ping && \
    mkdir /var/run/sshd && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user for SSH access
RUN useradd -m -s /bin/bash dev && \
    echo 'dev:dev' | chpasswd && \
    mkdir -p /var/log/bastion && \
    chown dev:dev /var/log/bastion && \
    chmod 755 /var/log/bastion

# copy nsswitch.conf to allow libnss-extrausers
# THIS IS THE CRITICAL PART MISSING - SSHD needs to know about users that don't exist in /etc/passwd
# Actually, for this design: users MUST exist in the OS for SSHD to accept them
# UNLESS we use libpam-script or similar. 
# BUT wait, the design of this project seems to rely on Mapping everyone to a single user OR creating users on the fly?
# Let's check sshd_config.

# Copy custom sshd_config (with AuthorizedKeysCommand)
COPY sshd_config /etc/ssh/sshd_config

# Generate host keys on start if missing (Ubuntu image doesn't have them)
CMD ["sh", "-c", "ssh-keygen -A && /usr/sbin/sshd -D -e"]

# Copy fetch-bastian-keys script for dynamic key fetching
COPY fetch-bastian-keys /usr/local/bin/fetch-bastian-keys
RUN chmod 755 /usr/local/bin/fetch-bastian-keys

# Copy wrapper script
COPY bastion_wrapper.sh /usr/local/bin/bastion_wrapper.sh
RUN chmod 755 /usr/local/bin/bastion_wrapper.sh

# Copy Rust binary
COPY bastion_cli/target/x86_64-unknown-linux-musl/release/bastion_cli /usr/local/bin/bastion_cli
RUN chmod +x /usr/local/bin/bastion_cli

# Create log directory for session recordings
RUN mkdir -p /var/log/bastion && chown dev:dev /var/log/bastion && chmod 755 /var/log/bastion

# Start sshd with host key generation
CMD ["sh", "-c", "ssh-keygen -A && /usr/sbin/sshd -D -e"]


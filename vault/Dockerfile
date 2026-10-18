# ZVault quantum-safe vault on IBM LinuxONE (s390x) - and any other Linux.
# Debian 13 gives OpenSSL 3.5 (ML-KEM-768, ML-DSA-65) and pre-built numpy / scikit-learn / pandas
# for s390x (pip has no s390x wheels for them). The code is NOT copied in: the vault/ folder is
# mounted at run time, so the image is just the runtime.
#
#   sudo docker build -t zvault-vault ~/botsbank-project/vault
#   sudo docker run --rm --network none --user "$(id -u):$(id -g)" \
#        -v ~/botsbank-project/vault:/vault zvault-vault                       # 83 tests
#   ... same ... zvault-vault python3 train_qshelf.py                           # train the model
#   ... same ... zvault-vault python3 run_demo.py                               # full demo
FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-numpy python3-sklearn python3-pandas python3-pytest \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /vault
CMD ["python3", "-m", "pytest", "-q", "-p", "no:cacheprovider"]

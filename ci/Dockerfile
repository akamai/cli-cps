FROM python:3-alpine3.19
ENV DEBIAN_FRONTEND=noninteractive
ENV PYENV_ROOT="/root/.pyenv"
ENV PATH="$PYENV_ROOT/bin:$PATH"

# Install dependencies and pyenv
# https://github.com/pyenv/pyenv/wiki#suggested-build-environment
RUN apk add --no-cache --virtual .build-deps \
    git build-base libffi-dev openssl-dev bzip2-dev zlib-dev xz-dev readline-dev sqlite-dev tk-dev curl \
 && apk add --no-cache bash \
 && curl -sSL https://pyenv.run | bash \
 && pyenv install 3.10 3.11 3.12 3.13 \
 && echo 'eval "$(pyenv init -)"' >> ~/.profile \
 && pip install --no-cache-dir tox \
 && apk del .build-deps \
 && rm -rf /var/cache/apk/* /root/.cache

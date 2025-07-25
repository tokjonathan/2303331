FROM node:alpine

RUN apk add --no-cache tini git \
    && yarn global add git-http-server \
    && adduser -D -g git git

USER git
WORKDIR /var/www/git

# Git identity for practical test
RUN git config --global user.name "Tok Yi Xun Jonathan" && \
    git config --global user.email "2303331@sit.singapore.tech.edu.sg"

RUN git init --bare repository.git

ENTRYPOINT ["tini", "--", "git-http-server", "-p", "4000", "/var/www/git"]

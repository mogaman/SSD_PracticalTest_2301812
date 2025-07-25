FROM node:alpine

RUN apk add --no-cache tini git \
    && yarn global add git-http-server\
    && adduser -D -g git git

RUN mkdir -p /var/git /home/git/.ssh && \
    chown -R git:git /var/git /home/git

USER git
WORKDIR /home/git

RUN git init --bare SSD_PracticalTest_2301812.git \
    && cd SSD_PracticalTest_2301812.git \
    && git config user.name "NG RAY EN, RYAN" \
    && git config user.email "2301812@sit.singaporetech.edu.sg"

ENTRYPOINT ["tini", "--", "git-http-server", "-p", "3000", "/home/git"]
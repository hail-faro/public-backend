# select a starting image to build off
FROM rust as build

# set our working directory in the container as /repo
WORKDIR /repo

# copy all our files across from our local repo to the /repo directory in the container
COPY Cargo.lock .
COPY Cargo.toml .
COPY .env .
COPY src src
# will need env files added
# COPY config  /.aws

# build the release
RUN cargo install --path .

# allow requests to port 3000
EXPOSE 3000

# this command is run when we actually start the container
CMD ["backend"]`
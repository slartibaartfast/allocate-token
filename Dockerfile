# Gather dependencies and build the executable
FROM golang:1.14 as builder

WORKDIR /go/src/agones.dev
# TODO: Clone from the latest release branch instead of from the master branch.
RUN git clone https://github.com/googleforgames/agones.git

WORKDIR /go/src/agones.dev/agones/examples/allocator-service
ADD ./main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o service .


# Create the final image that will run the allocator service
FROM alpine:3.8
RUN apk add --update ca-certificates
RUN adduser -D -u 1000 service

COPY --from=builder /go/src/agones.dev/agones/examples/allocator-service \
                    /home/service

RUN chown -R service /home/service && \
    chmod o+x /home/service/service

USER 1000
ENTRYPOINT /home/service/service

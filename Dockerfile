# Gather dependencies and build the executable
FROM golang:1.14 as builder

WORKDIR /go/src/github.com/slartibaartfast
COPY /home/trota/Code/cassandra/astra_gocql_connect/certs/cert \
     /home/service/certs/cert
COPY /home/trota/Code/cassandra/astra_gocql_connect/certs/key \
     /home/service/certs/key
COPY /home/trota/Code/cassandra/astra_gocql_connect/certs/ca.crt \
     /home/service/ca.crt
COPY /home/trota/Code/cassandra/astra_gocql_connect/certs/tls.crt \
     /home/service/certs/tls.crt
COPY /home/trota/Code/cassandra/astra_gocql_connect/certs/tls.key \
     /home/service/certs/tls.key

RUN git clone https://github.com/slartibaartfast/allocate-token.git

WORKDIR /go/src/github.com/slartibaartfast/allocate-token
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

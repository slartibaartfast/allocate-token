# Gather dependencies and build the executable
FROM golang:1.14 as builder

WORKDIR /go/src/github.com/slartibaartfast
RUN git clone https://github.com/slartibaartfast/allocate-token.git
RUN go get github.com/gocql/gocql

WORKDIR /go/src/github.com/slartibaartfast/allocate-token
ADD ./main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o service .


# Create the final image that will run the token allocation service
FROM alpine:3.12
RUN apk add --update ca-certificates
RUN adduser -D -u 1000 service

COPY --from=builder /go/src/github.com/slartibaartfast/allocate-token \
                    /home/service

RUN chown -R service /home/service && \
    chmod o+x /home/service/service && \
    mkdir /home/service/logs && \
    chmod o+rw /home/service/logs

USER service
ENTRYPOINT /home/service/service

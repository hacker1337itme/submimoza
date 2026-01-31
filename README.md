# submimoza
submimoz

# BUILD

```
go mod init submimoza.go
go mod tidy
go build -o submimoza submimoza.go
```

# USAGE

```
# Scan single URL
./submimoza https://example.com

# Scan multiple URLs
./submimoza https://example1.com https://example2.com

# Read URLs from file
./submimoza -f urls.txt

# Pipe URLs from stdin
cat urls.txt | ./submimoza
```

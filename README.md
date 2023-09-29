# JA4X for Go

An implementation of the (JA4X hash algorithm)[https://github.com/FoxIO-LLC/ja4] in Go.

# Command-line usage

Compile:

```
go build -o ja4x cmd/ja4x/main.go
```

Extract JA4X for a certificate:

```
./ja4x example_com.pem 
ja4x: a373a9f83c6b_2bab15409345_7bf9a7bf7029
```

Extract JA4X for a certificate, including raw version:

``````
./ja4x -r example_com.pem
ja4x: a373a9f83c6b_2bab15409345_7bf9a7bf7029
ja4x_r: 550406,55040a,550403_550406,550408,550407,55040a,550403_551d23,551d0e,551d11,551d0f,551d25,551d1f,551d20,2b06010505070101,551d13,2b06010401d679020402
```

Certificates can be supplied raw, or PEM encoded.

# Usage as a library

Add to your project:

```
go get github.com/driftnet-io/ja4x
```

Then call either

```
func JA4X(cert *x509.Certificate) string
```

or if you want the raw version as well,

```
func JA4XWithRaw(cert *x509.Certificate) (string, string)
```

# Licensing

The code in this repository is MIT licensed. However, JA4X itself is subject to additional restricitons. Please see the NOTICE file for further details.

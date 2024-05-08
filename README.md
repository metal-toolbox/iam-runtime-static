# iam-runtime-static - A simple IAM runtime implementation with static credentials

iam-runtime-static is an [IAM runtime][iam-runtime] implementation that uses static credentials in environment variables for authenticating and authorizing subjects. This provides a way to integrate IAM functionality into an application in local development environments without needing to include extraneous services or mocks in application code.

[iam-runtime]: https://github.com/metal-toolbox/iam-runtime

## Usage

iam-runtime-static can be run as a standalone binary or a container (i.e., when running Docker Compose applications).

To run it as a standalone binary using the example policy and a socket in `/tmp`, use the following commands:

```
$ go build -mod=readonly -o bin/ .
$ ALICE_TOKEN=a1ic3 BOB_TOKEN=B0b ./bin/iam-runtime-static serve --policy policy.example.yaml --listen /tmp/runtime.sock --pretty
```

## Configuration

To configure iam-runtime-static, you must define the static tokens that correspond to subjects and the resources those subjects have access to. An [example policy][example-policy] is available in this repository.

Additionally you may configure the Identity service by providing a config file with additional access token configuration.
An [example config][example-config] is available in this repository.

[example-policy]: ./policy.example.yaml
[example-config]: ./config.example.yaml

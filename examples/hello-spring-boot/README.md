# hello-spring-boot

Minimal Spring Boot example using [`sdks/jvm/arc-spring-boot`](../../sdks/jvm/arc-spring-boot/).

## What It Demonstrates

- `GET /hello` and `POST /echo` behind the real ARC servlet filter
- deny without capability and allow with a trust-issued capability token
- request body remains readable by the controller after ARC hashing
- receipt ids are emitted on the response header path

## Files

```text
README.md
build.gradle.kts
settings.gradle.kts
src/main/kotlin/...
openapi.yaml
policy.yaml
run.sh
smoke.sh
```

## Run

Start the app only:

```bash
./run.sh
```

Run the full end-to-end smoke flow:

```bash
./smoke.sh
```
